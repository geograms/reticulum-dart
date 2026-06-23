/*
 * In-process file-transfer round-trip tests — the regression lock for the file
 * layer over Reticulum. Two FileTransferNodes are wired together with send
 * callbacks that parse + route packets between them (no sockets), exercising the
 * full link handshake + whole-file Resource (GET_FILE) path exactly as on the
 * wire. A whole file rides ONE Resource (segmented/HMU/windowed by the Resource
 * layer), so large files (55 MB, 107 MB) transfer with no size cap.
 */
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// One side of a 2-node loopback: parses raw bytes back into packets and feeds
/// them to its node one at a time (mirrors how the real transport delivers).
class _Loop {
  late FileTransferNode node;
  final List<RnsPacket> _inbox = [];
  bool _pumping = false;

  void deliver(Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    _inbox.add(p);
    _pump();
  }

  Future<void> _pump() async {
    if (_pumping) return;
    _pumping = true;
    while (_inbox.isNotEmpty) {
      final p = _inbox.removeAt(0);
      try {
        await node.handlePacket(p);
      } catch (_) {/* a wrong-peer packet is ignored, as on the wire */}
    }
    _pumping = false;
  }
}

/// Deterministic pseudo-random bytes of [n] (reproducible across runs).
Uint8List _bytes(int n, {int seed = 1}) {
  final out = Uint8List(n);
  var x = (seed * 2654435761) & 0xffffffff;
  for (var i = 0; i < n; i++) {
    x = (1103515245 * x + 12345) & 0x7fffffff;
    out[i] = (x >> 16) & 0xff;
  }
  return out;
}

Uint8List _sha(Uint8List b) =>
    Uint8List.fromList(crypto.sha256.convert(b).bytes);

/// A FileSource that holds one file but serves CORRUPTED bytes for it — the
/// assembled content won't hash to the requested id, so the fetcher must reject it.
class _CorruptSource implements FileSource {
  final Uint8List corrupt;
  _CorruptSource(this.corrupt);
  @override
  Uint8List? read(Uint8List fileHash) => corrupt;
}

void main() {
  /// Build provider (holds [providerSource]) + fetcher, wired loopback. Returns
  /// the fetcher node and the provider's public identity to fetch from.
  Future<(FileTransferNode fetcher, RnsIdentity providerPub)> pair(
      FileSource providerSource) async {
    final provId = await RnsIdentity.generate();
    final fetchId = await RnsIdentity.generate();
    final loopProvider = _Loop();
    final loopFetcher = _Loop();
    loopProvider.node = FileTransferNode(
      identity: provId,
      source: providerSource,
      send: (raw) => loopFetcher.deliver(raw),
    );
    loopFetcher.node = FileTransferNode(
      identity: fetchId,
      source: const EmptyFileSource(),
      send: (raw) => loopProvider.deliver(raw),
    );
    final provPub = RnsIdentity.fromPublicKey(provId.getPublicKey());
    return (loopFetcher.node, provPub);
  }

  group('whole-file transfer (GET_FILE, single Resource)', () {
    for (final spec in const [
      ('1 MB', 1024 * 1024),
      ('10 MB', 10 * 1024 * 1024),
      ('55 MB', 55 * 1024 * 1024),
      ('107 MB', 107 * 1024 * 1024), // no size cap (multi-segment Resource)
    ]) {
      test('round-trips ${spec.$1} and verifies', () async {
        final file = _bytes(spec.$2, seed: spec.$2);
        final hash = _sha(file);
        final src = MemoryFileSource()..add(file);
        final (fetcher, provPub) = await pair(src);

        final got = await fetcher.fetch(hash, provPub,
            timeout: const Duration(minutes: 5));
        expect(got, isNotNull, reason: 'fetch returned null for ${spec.$1}');
        expect(got!.length, file.length);
        expect(_sha(got), equals(hash), reason: 'assembled hash mismatch');
      }, timeout: const Timeout(Duration(minutes: 6)));
    }

    test('round-trips an empty file', () async {
      final file = Uint8List(0);
      final hash = _sha(file);
      final src = MemoryFileSource()..add(file);
      final (fetcher, provPub) = await pair(src);
      final got = await fetcher.fetch(hash, provPub);
      expect(got, isNotNull);
      expect(got!.length, 0);
      expect(_sha(got), equals(hash));
    });

    test('returns null when the provider does not hold the file', () async {
      final want = _sha(_bytes(1000, seed: 7));
      final (fetcher, provPub) = await pair(MemoryFileSource());
      final got =
          await fetcher.fetch(want, provPub, timeout: const Duration(seconds: 5));
      expect(got, isNull);
    });

    test('rejects a corrupting provider (content-address check)', () async {
      final real = _bytes(200 * 1024, seed: 99);
      final realHash = _sha(real);
      final corrupt = Uint8List.fromList(real)..[123] ^= 0xff; // flip a byte
      final (fetcher, provPub) = await pair(_CorruptSource(corrupt));
      final got = await fetcher.fetch(realHash, provPub,
          timeout: const Duration(seconds: 10));
      expect(got, isNull, reason: 'tampered bytes must not verify as the id');
    });
  });
}
