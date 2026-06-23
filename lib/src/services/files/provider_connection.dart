/*
 * ProviderConnection — an initiator-side link to ONE provider's files
 * destination that can request the manifest and arbitrary chunks on demand. This
 * is the per-source handle the multi-source orchestrator drives: it opens several
 * (one per provider) and pulls different chunks from each in parallel.
 *
 * One request is outstanding at a time per connection (a provider serves one
 * Resource per link); the orchestrator runs exactly one worker per connection, so
 * no internal queueing is needed here. Transport-agnostic: the owner supplies a
 * [send] callback and routes inbound packets to [onPacket].
 */
import 'dart:async';
import 'dart:typed_data';

import '../reticulum/rns_link.dart';
import '../reticulum/rns_packet.dart';
import '../reticulum/rns_resource_receiver.dart';
import 'file_manifest.dart';
import 'file_transfer.dart';

class ProviderConnection {
  final RnsLink link;
  final void Function(Uint8List raw) send;

  final Completer<bool> _readyC = Completer<bool>();
  Completer<Uint8List?>? _pending; // current request
  RnsResourceReceiver? _rx;
  Timer? _reqTimer;
  bool _closed = false;

  ProviderConnection(this.link, this.send);

  /// Resolves true once the link handshake completes (false on failure/timeout).
  Future<bool> ready({Duration timeout = const Duration(seconds: 12)}) =>
      _readyC.future.timeout(timeout, onTimeout: () => false);

  bool get isReady => _readyC.isCompleted;

  /// Fetch + decode the manifest for [sha256] via the segmented protocol: ask for
  /// its byte length, then pull it in <=34 KB parts and reassemble. Handles
  /// arbitrarily large manifests (large files). Null if the provider lacks it.
  Future<FileManifest?> getManifestSegmented(Uint8List sha256) async {
    final info = await _request(_cmd(kOpGetManifestInfo, sha256));
    if (info == null || info.length < 1 + 32 + 4 || info[0] != kOpManifestInfo) {
      return null;
    }
    final manifestLen =
        ByteData.sublistView(info, 33, 37).getUint32(0, Endian.big);
    if (manifestLen <= 0) return null;
    final buf = BytesBuilder();
    var idx = 0;
    while (buf.length < manifestLen) {
      final part = await _request(_manifestPartCmd(sha256, idx));
      if (part == null) return null;
      buf.add(part);
      idx++;
    }
    if (buf.length != manifestLen) return null;
    return FileManifest.decode(buf.toBytes());
  }

  /// Legacy single-Resource manifest fetch (small files only; kept for talking to
  /// not-yet-updated providers). Prefer [getManifestSegmented].
  Future<FileManifest?> getManifest(Uint8List sha256) async {
    final bytes = await _request(_cmd(kOpGetManifest, sha256));
    return bytes == null ? null : FileManifest.decode(bytes);
  }

  /// Fetch chunk [idx] of [sha256] (raw bytes; the caller verifies the hash).
  Future<Uint8List?> getChunk(Uint8List sha256, int idx) =>
      _request(_chunkCmd(sha256, idx));

  void close() {
    _closed = true;
    _reqTimer?.cancel();
    _complete(null);
  }

  /// Route one inbound packet for this connection's link.
  Future<void> onPacket(RnsPacket p) async {
    if (_closed) return;
    if (!_readyC.isCompleted) {
      // Handshake: validate the provider's proof, send LRRTT, become ready.
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await link.handleProof(p);
        if (rtt == null) {
          _readyC.complete(false);
          return;
        }
        send(rtt.pack());
        _readyC.complete(true);
      }
      return;
    }
    switch (p.context) {
      case RnsContext.none:
        final cmd = link.decrypt(p);
        if (cmd.isEmpty) break;
        if (cmd[0] == kOpNotFound) {
          _complete(null);
        } else if (cmd[0] == kOpManifestInfo) {
          // The descriptor reply rides a context-none DATA packet, not a
          // Resource — hand it straight to the pending request.
          _complete(cmd);
        }
        break;
      case RnsContext.resourceAdv:
        final rx = RnsResourceReceiver(link);
        _rx = rx;
        if (!rx.ingestAdvertisement(link.decrypt(p))) {
          _complete(null);
          break;
        }
        send(rx.buildRequest().pack());
        break;
      case RnsContext.resource:
        final rx = _rx;
        if (rx == null) break;
        final done = rx.ingestPart(p.data);
        if (rx.error != null) {
          _complete(null);
          break;
        }
        if (done) {
          final prf = rx.proofPacket();
          if (prf != null) send(prf.pack());
          _complete(rx.payload);
        }
        break;
      default:
        break;
    }
  }

  Future<Uint8List?> _request(RnsPacket cmd) {
    if (_pending != null) {
      throw StateError('ProviderConnection: one request at a time');
    }
    final c = Completer<Uint8List?>();
    _pending = c;
    _reqTimer = Timer(const Duration(seconds: 20), () => _complete(null));
    send(cmd.pack());
    return c.future;
  }

  void _complete(Uint8List? v) {
    _reqTimer?.cancel();
    _reqTimer = null;
    _rx = null;
    final c = _pending;
    _pending = null;
    if (c != null && !c.isCompleted) c.complete(v);
  }

  RnsPacket _cmd(int op, Uint8List sha) {
    final b = BytesBuilder()
      ..addByte(op)
      ..add(sha);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _chunkCmd(Uint8List sha, int idx) {
    final b = BytesBuilder()
      ..addByte(kOpGetChunk)
      ..add(sha);
    final n = ByteData(4)..setUint32(0, idx, Endian.big);
    b.add(n.buffer.asUint8List());
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _manifestPartCmd(Uint8List sha, int idx) {
    final b = BytesBuilder()
      ..addByte(kOpGetManifestPart)
      ..add(sha);
    final n = ByteData(4)..setUint32(0, idx, Endian.big);
    b.add(n.buffer.asUint8List());
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }
}
