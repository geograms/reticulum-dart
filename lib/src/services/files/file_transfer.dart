/*
 * File transfer protocol over an established RNS Link.
 *
 * Transport-agnostic session state machines drive one provider<->fetcher link.
 * They consume inbound RnsPackets (already routed to this link) and return the
 * RnsPackets to send back, so they can be wired to any interface and unit-tested
 * in-process. A whole file rides ONE RNS Resource (the Resource layer segments,
 * windows and HMUs it for arbitrary size); small commands ride a link-encrypted
 * DATA packet with context=none.
 *
 * Wire commands (plaintext of a context-none link DATA):
 *   0x01 GET_FILE   + fileHash(32)                 (fetch the whole file)
 *   0x81 NOT_FOUND  + fileHash(32)                 (provider -> fetcher)
 *
 * A GET_FILE is answered with the file's bytes as a single Resource. Integrity:
 * the Resource verifies each part + each segment; the fetcher additionally checks
 * sha256(assembled) == the requested file id, binding an untrusted transfer to the
 * content the caller asked for.
 *
 * Store-and-forward deposit (a peer asks a host to KEEP a blob it doesn't hold):
 *   client -> host : 0x03 PUT_OFFER  sha(32) size(8 BE) extLen(1) ext pub(32) sig(64)
 *   host -> client : 0x84 PUT_ACCEPT sha(32)            (send the bytes now)
 *   host -> client : 0x82 PUT_REJECT reason(utf8)
 *   client -> host : the blob as an RNS Resource (client = sender, host = receiver)
 *   host -> client : 0x85 PUT_STORED sha(32)
 * The compact auth proves a NOSTR identity authorizes hosting THIS sha: sig is a
 * BIP-340 Schnorr signature by [pub] over sha256("blossom-deposit:"+shaHex).
 */
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../reticulum/rns_link.dart';
import '../reticulum/rns_packet.dart';
import '../reticulum/rns_resource.dart';
import '../reticulum/rns_resource_receiver.dart';
import 'serve_quota.dart';

const int kOpGetFile = 0x01;
const int kOpNotFound = 0x81;
const int kOpPutOffer = 0x03;
const int kOpPutReject = 0x82;
const int kOpPutAccept = 0x84;
const int kOpPutStored = 0x85;

/// The canonical message a depositor Schnorr-signs to authorize hosting [shaHex]
/// (returned as 64-char hex, ready for NostrCrypto.schnorrSign/Verify).
String depositAuthMessageHex(String shaHex) =>
    _hex(crypto.sha256.convert(utf8.encode('blossom-deposit:$shaHex')).bytes);

/// A host's decision on an inbound deposit offer.
class DepositVerdict {
  final bool ok;
  final String? reason; // set when !ok
  final int tier; // 0 self / 1 followed / 2 stranger
  final String originPubHex; // depositor's NOSTR pubkey
  final String ext; // file extension to store under
  const DepositVerdict.accept(this.tier, this.originPubHex, this.ext)
      : ok = true,
        reason = null;
  const DepositVerdict.reject(this.reason)
      : ok = false,
        tier = 2,
        originPubHex = '',
        ext = 'bin';
}

/// Where a serving node reads content it holds, by file id (sha256, 32B).
abstract class FileSource {
  /// Whole-file bytes for [fileHash], or null if this node does not hold it.
  Uint8List? read(Uint8List fileHash);
}

/// A [FileSource] that holds nothing (default for a node that only fetches).
class EmptyFileSource implements FileSource {
  const EmptyFileSource();
  @override
  Uint8List? read(Uint8List fileHash) => null;
}

/// An in-memory [FileSource] (tests, small caches). Keyed by lowercase hex.
class MemoryFileSource implements FileSource {
  final Map<String, Uint8List> _byHex = {};
  void add(Uint8List bytes) =>
      _byHex[_hex(crypto.sha256.convert(bytes).bytes)] = bytes;
  @override
  Uint8List? read(Uint8List fileHash) => _byHex[_hex(fileHash)];
}

// ── Provider side ──────────────────────────────────────────────────────────

/// Serves files to one connected fetcher over an active link. One file (one
/// Resource, possibly multi-segment) is served at a time.
class FileServeSession {
  final RnsLink link;
  final FileSource source;
  final ServeQuota? quota; // optional serving budget / anti-abuse guard
  final String requesterId; // best-effort requester key (the link id)
  /// Called once per download a peer starts (when we begin serving a file), with
  /// the 32-byte file hash — drives the per-file download metric.
  final void Function(Uint8List fileHash)? onServed;

  /// Store-and-forward deposit hooks (null = this node does not accept deposits).
  final DepositVerdict Function(
      Uint8List sha, int size, String ext, String pubHex, String sigHex)?
      onDepositOffer;
  final void Function(
      Uint8List sha, Uint8List bytes, String originPubHex, int tier, String ext)?
      onDepositStore;

  RnsResourceSender? _sender; // current in-flight resource (serving)
  RnsResourceReceiver? _rx; // current in-flight resource (deposit receive)
  Uint8List? _depSha;
  int _depTier = 2;
  String _depOrigin = '';
  String _depExt = 'bin';

  final void Function(String msg)? log;

  FileServeSession(this.link, this.source,
      {this.quota,
      this.requesterId = '',
      this.onServed,
      this.onDepositOffer,
      this.onDepositStore,
      this.log});

  void _abortDeposit() {
    _rx = null;
    _depSha = null;
  }

  /// Process one inbound packet for this link; returns packets to send back.
  List<RnsPacket> onPacket(RnsPacket p) {
    switch (p.context) {
      case RnsContext.resourceReq:
        // Serving: a part request (or an HMU request, 0xFF) for the file we send.
        final s = _sender;
        if (s == null) {
          log?.call('serve: REQ but no active sender');
          return const [];
        }
        final req = link.decrypt(p);
        final out = s.handleRequest(req);
        // Only log HMU (exhausted) requests — low volume, the interesting ones
        // for diagnosing multi-segment/hashmap stalls. Per-part requests are far
        // too frequent to log per-packet.
        if (log != null && req.isNotEmpty && req[0] == 0xFF) {
          final hmu =
              out.where((x) => x.context == RnsContext.resourceHmu).length;
          final parts =
              out.where((x) => x.context == RnsContext.resource).length;
          log!('serve: HMU req seg=${s.segmentIndex} -> hmu=$hmu parts=$parts');
        }
        return out;
      case RnsContext.resourcePrf:
        // Serving: a per-segment proof. Advance + advertise the next segment.
        // RNS sends resource proofs UNENCRYPTED (RNS/Packet.py RESOURCE_PRF), so
        // validate the raw packet data — do NOT link.decrypt() it.
        final s = _sender;
        if (s == null) return const [];
        if (s.validateProof(p.data)) {
          log?.call('serve: PROOF ok complete=${s.complete}');
          if (!s.complete) return [s.advertisementPacket()];
          _sender = null;
        } else {
          log?.call('serve: PROOF INVALID');
        }
        return const [];
      case RnsContext.resourceAdv:
        // Inbound deposit bytes: only when we accepted an offer.
        if (_depSha == null) return const [];
        final rx = RnsResourceReceiver(link);
        _rx = rx;
        if (!rx.ingestAdvertisement(link.decrypt(p))) {
          _abortDeposit();
          return [_putReject('bad advertisement')];
        }
        return _depositAfterReceive(rx);
      case RnsContext.resourceHmu:
        final rx = _rx;
        if (rx == null) return const [];
        rx.ingestHmu(link.decrypt(p));
        return rx.pump();
      case RnsContext.resource:
        final rx = _rx;
        if (rx == null) return const [];
        rx.ingestPart(p.data);
        if (rx.error != null) {
          _abortDeposit();
          return [_putReject('resource error')];
        }
        return _depositAfterReceive(rx);
      case RnsContext.none:
        return _onCommand(link.decrypt(p));
      default:
        return const [];
    }
  }

  // Drive the deposit receiver: keep the window full; on segment completion send
  // the proof; on full completion verify the sha and store.
  List<RnsPacket> _depositAfterReceive(RnsResourceReceiver rx) {
    if (rx.segmentComplete) {
      final out = <RnsPacket>[];
      final prf = rx.proofPacket();
      if (prf != null) out.add(prf);
      if (rx.complete) {
        final bytes = rx.payload!;
        final h = Uint8List.fromList(crypto.sha256.convert(bytes).bytes);
        if (_eq(h, _depSha!)) {
          onDepositStore?.call(_depSha!, bytes, _depOrigin, _depTier, _depExt);
          out.add(_putStored(_depSha!));
        } else {
          out.add(_putReject('hash mismatch'));
        }
        _abortDeposit();
      }
      return out;
    }
    return rx.pump();
  }

  List<RnsPacket> _onCommand(Uint8List cmd) {
    if (cmd.isEmpty) return const [];
    final op = cmd[0];
    if (op == kOpGetFile && cmd.length >= 1 + 32) {
      final fileHash = Uint8List.sublistView(cmd, 1, 33);
      final bytes = source.read(fileHash);
      if (bytes == null) return [_notFound(fileHash)];
      if (!_allow(fileHash, bytes.length)) return [_notFound(fileHash)];
      onServed?.call(Uint8List.fromList(fileHash));
      return _serveResource(bytes, fileHash);
    }
    if (op == kOpPutOffer && cmd.length >= 1 + 32 + 8 + 1) {
      // [0x03][sha32][size8][extLen1][ext][pub32][sig64]
      final sha = Uint8List.sublistView(cmd, 1, 33);
      final size = ByteData.sublistView(cmd, 33, 41).getUint64(0, Endian.big);
      final extLen = cmd[41];
      var o = 42;
      if (cmd.length < o + extLen + 32 + 64) return [_putReject('bad offer')];
      final ext = String.fromCharCodes(cmd.sublist(o, o + extLen));
      o += extLen;
      final pub = Uint8List.sublistView(cmd, o, o + 32);
      o += 32;
      final sig = Uint8List.sublistView(cmd, o, o + 64);
      final accept = onDepositOffer?.call(sha, size, ext, _hex(pub), _hex(sig));
      if (accept == null || !accept.ok) {
        return [_putReject(accept?.reason ?? 'deposits not accepted')];
      }
      _depSha = sha;
      _depTier = accept.tier;
      _depOrigin = accept.originPubHex;
      _depExt = accept.ext.isNotEmpty ? accept.ext : ext;
      return [_putAccept(sha)];
    }
    return const [];
  }

  RnsPacket _putAccept(Uint8List sha) {
    final b = BytesBuilder()
      ..addByte(kOpPutAccept)
      ..add(sha);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _putStored(Uint8List sha) {
    final b = BytesBuilder()
      ..addByte(kOpPutStored)
      ..add(sha);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _putReject(String reason) {
    final b = BytesBuilder()
      ..addByte(kOpPutReject)
      ..add(utf8.encode(reason));
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  // Quota gate: may we serve [bytes] for [fileHash] to this requester now?
  bool _allow(Uint8List fileHash, int bytes) {
    final q = quota;
    if (q == null) return true;
    return q.canServe(requesterId, fileHash, bytes);
  }

  List<RnsPacket> _serveResource(Uint8List payload, Uint8List fileHash) {
    final s = RnsResourceSender(link, payload);
    s.prepare();
    _sender = s;
    quota?.record(requesterId, fileHash, payload.length);
    return [s.advertisementPacket()];
  }

  RnsPacket _notFound(Uint8List fileHash) {
    final b = BytesBuilder()
      ..addByte(kOpNotFound)
      ..add(fileHash);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }
}

// ── Fetcher side ───────────────────────────────────────────────────────────

enum FileFetchState { idle, fetching, done, failed }

/// Fetches one file (by id) from one provider over an active link: GET_FILE, then
/// drive the RnsResourceReceiver (windowed parts, HMU, multi-segment) to
/// completion, verifying sha256(assembled) == the requested id.
class FileFetchSession {
  final RnsLink link;
  final Uint8List wantHash; // requested file id (sha256, 32B)

  FileFetchState state = FileFetchState.idle;
  String? error;
  Uint8List? result; // assembled, verified file bytes

  late final RnsResourceReceiver _rx = RnsResourceReceiver(link);

  FileFetchSession(this.link, this.wantHash);

  /// Bytes received so far (for a progress display).
  int get receivedBytes => _rx.receivedBytes;

  /// Total size is unknown until the transfer completes (segments are advertised
  /// one at a time), so progress is indeterminate; returns 0.
  int get totalBytes => 0;

  /// Begin: returns the GET_FILE packet to send.
  RnsPacket start() {
    state = FileFetchState.fetching;
    return _cmd(kOpGetFile, wantHash);
  }

  /// Process one inbound packet; returns packets to send back. When [state]
  /// becomes done, [result] holds the verified file; on failed, [error] is set.
  List<RnsPacket> onPacket(RnsPacket p) {
    if (state == FileFetchState.done || state == FileFetchState.failed) {
      return const [];
    }
    if (p.context == RnsContext.none) {
      final cmd = link.decrypt(p);
      if (cmd.isNotEmpty && cmd[0] == kOpNotFound) {
        return _fail('provider does not have the file');
      }
      return const [];
    }
    // resourceAdv / resourceHmu / resource → the shared multi-segment driver.
    final out = _rx.handle(p);
    if (_rx.error != null) return _fail('resource error: ${_rx.error}');
    if (_rx.complete) _finish();
    return out;
  }

  /// Re-request stalled parts (call on a stall timer).
  List<RnsPacket> retry() => _rx.retry();

  void _finish() {
    final bytes = _rx.payload;
    if (bytes == null) {
      _fail('no payload after completion');
      return;
    }
    final h = Uint8List.fromList(crypto.sha256.convert(bytes).bytes);
    if (!_eq(h, wantHash)) {
      _fail('assembled file hash != requested id');
      return;
    }
    result = bytes;
    state = FileFetchState.done;
  }

  List<RnsPacket> _fail(String why) {
    error = why;
    state = FileFetchState.failed;
    return const [];
  }

  RnsPacket _cmd(int op, Uint8List arg) {
    final b = BytesBuilder()
      ..addByte(op)
      ..add(arg);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }
}

// ── Deposit side (client asks a host to keep a blob) ─────────────────────────

enum FileDepositState { idle, offered, sending, done, failed }

/// Deposits one blob to a host over an active link: offer (with compact auth),
/// then on accept stream the bytes as an RNS Resource, then await PUT_STORED.
class FileDepositSession {
  final RnsLink link;
  final Uint8List sha; // sha256(bytes), 32B
  final Uint8List bytes;
  final String ext;
  final Uint8List pub; // depositor NOSTR pubkey, 32B (x-only)
  final Uint8List sig; // Schnorr sig over depositAuthMessageHex(shaHex), 64B

  FileDepositState state = FileDepositState.idle;
  String? error;
  RnsResourceSender? _sender;

  FileDepositSession(this.link, this.sha, this.bytes, this.ext, this.pub, this.sig);

  /// Begin: returns the PUT_OFFER packet to send.
  RnsPacket start() {
    state = FileDepositState.offered;
    final extB = ascii.encode(ext);
    final b = BytesBuilder()
      ..addByte(kOpPutOffer)
      ..add(sha);
    final sz = ByteData(8)..setUint64(0, bytes.length, Endian.big);
    b
      ..add(sz.buffer.asUint8List())
      ..addByte(extB.length)
      ..add(extB)
      ..add(pub)
      ..add(sig);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  List<RnsPacket> onPacket(RnsPacket p) {
    if (state == FileDepositState.done || state == FileDepositState.failed) {
      return const [];
    }
    switch (p.context) {
      case RnsContext.none:
        final cmd = link.decrypt(p);
        if (cmd.isEmpty) return const [];
        if (cmd[0] == kOpPutAccept) {
          // Host accepted — stream the bytes as a Resource.
          final s = RnsResourceSender(link, bytes);
          s.prepare();
          _sender = s;
          state = FileDepositState.sending;
          return [s.advertisementPacket()];
        }
        if (cmd[0] == kOpPutReject) {
          return _fail(utf8.decode(cmd.sublist(1), allowMalformed: true));
        }
        if (cmd[0] == kOpPutStored) {
          state = FileDepositState.done;
          return const [];
        }
        return const [];
      case RnsContext.resourceReq:
        final s = _sender;
        if (s == null) return const [];
        return s.handleRequest(link.decrypt(p));
      case RnsContext.resourcePrf:
        final s = _sender;
        if (s == null) return const [];
        // RNS resource proofs are UNENCRYPTED — validate raw p.data.
        if (s.validateProof(p.data) && !s.complete) {
          return [s.advertisementPacket()]; // next segment
        }
        return const []; // success is confirmed by PUT_STORED
      default:
        return const [];
    }
  }

  List<RnsPacket> _fail(String why) {
    error = why;
    state = FileDepositState.failed;
    return const [];
  }
}

bool _eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
