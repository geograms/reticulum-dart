/*
 * In-process file-transfer round-trip tests — the regression lock for binary
 * transfer over Reticulum. Two FileTransferNodes are wired together with send
 * callbacks that parse + route packets between them (no sockets), exercising the
 * full link handshake + segmented-manifest + chunk protocol exactly as it runs
 * on the wire.
 *
 * The headline cases prove the large-file fix (segmented manifest): a 55 MB file
 * — whose ~57 KB manifest overflows a single RNS Resource and used to be declined
 * — now transfers and verifies. Smaller sizes, the empty file, a not-held file,
 * and a corrupting provider (integrity rejection) round out the coverage.
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
      } catch (_) {/* a wrong-peer packet is simply ignored, as on the wire */}
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

/// A FileSource that holds one file but serves CORRUPTED bytes for it — its
/// reported manifest (computed from the corrupt bytes here) won't match the
/// requested id, and chunk content won't match a manifest built from the real
/// file, so the fetcher must reject it.
class _CorruptSource implements FileSource {
  final Uint8List realHash;
  final Uint8List corrupt;
  _CorruptSource(this.realHash, this.corrupt);
  @override
  Uint8List? read(Uint8List fileHash) {
    // Answer for the requested (real) id, but hand back tampered bytes.
    return corrupt;
  }
}

/// A FileSource that holds the file but "dies" after [failAfterReads] reads
/// (returns null thereafter) — simulates a provider that drops mid-transfer, so
/// the multi-source fetcher must requeue its chunks to another provider.
class _FlakySource implements FileSource {
  final Uint8List bytes;
  final int failAfterReads;
  int _reads = 0;
  _FlakySource(this.bytes, this.failAfterReads);
  @override
  Uint8List? read(Uint8List fileHash) {
    _reads++;
    return _reads <= failAfterReads ? bytes : null;
  }
}

/// A broadcast bus: every node's outbound packet is delivered to every OTHER
/// node (each ignores packets not addressed to one of its links), each node's
/// inbox processed one packet at a time. Models multi-provider fan-out.
class _Bus {
  final List<_BusNode> _nodes = [];
  _BusNode attach(FileTransferNode Function(void Function(Uint8List)) build) {
    final n = _BusNode(this);
    n.node = build(n.send);
    _nodes.add(n);
    return n;
  }

  void deliverFrom(_BusNode from, Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    for (final n in _nodes) {
      if (identical(n, from)) continue;
      n.enqueue(p);
    }
  }
}

class _BusNode {
  final _Bus bus;
  late final FileTransferNode node;
  final List<RnsPacket> _inbox = [];
  bool _pumping = false;
  _BusNode(this.bus);
  void send(Uint8List raw) => bus.deliverFrom(this, raw);
  void enqueue(RnsPacket p) {
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
      } catch (_) {}
    }
    _pumping = false;
  }
}

void main() {
  /// Build provider (holds [file]) + fetcher, wired loopback. Returns the fetcher
  /// node and the provider's public identity to fetch from.
  Future<(FileTransferNode fetcher, RnsIdentity providerPub)> _pair(
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

  group('segmented-manifest file transfer (loopback)', () {
    for (final spec in const [
      ('1 MB', 1024 * 1024),
      ('10 MB', 10 * 1024 * 1024),
      ('55 MB', 55 * 1024 * 1024), // the case that used to fail (manifest > 1 Resource)
    ]) {
      test('round-trips ${spec.$1} and verifies', () async {
        final file = _bytes(spec.$2, seed: spec.$2);
        final hash = _sha(file);
        final src = MemoryFileSource()..add(file);
        final (fetcher, provPub) = await _pair(src);

        final got = await fetcher.fetch(hash, provPub,
            timeout: const Duration(seconds: 120));
        expect(got, isNotNull, reason: 'fetch returned null for ${spec.$1}');
        expect(got!.length, file.length);
        expect(_sha(got), equals(hash), reason: 'assembled hash mismatch');
      }, timeout: const Timeout(Duration(minutes: 3)));
    }

    test('round-trips an empty file', () async {
      final file = Uint8List(0);
      final hash = _sha(file);
      final src = MemoryFileSource()..add(file);
      final (fetcher, provPub) = await _pair(src);
      final got = await fetcher.fetch(hash, provPub);
      expect(got, isNotNull);
      expect(got!.length, 0);
      expect(_sha(got), equals(hash));
    });

    test('returns null when the provider does not hold the file', () async {
      final want = _sha(_bytes(1000, seed: 7));
      final (fetcher, provPub) = await _pair(MemoryFileSource());
      final got =
          await fetcher.fetch(want, provPub, timeout: const Duration(seconds: 5));
      expect(got, isNull);
    });

    test('rejects a corrupting provider (integrity check)', () async {
      final real = _bytes(200 * 1024, seed: 99); // > 1 chunk
      final realHash = _sha(real);
      final corrupt = Uint8List.fromList(real)..[123] ^= 0xff; // flip a byte
      final (fetcher, provPub) = await _pair(_CorruptSource(realHash, corrupt));
      final got = await fetcher.fetch(realHash, provPub,
          timeout: const Duration(seconds: 10));
      expect(got, isNull, reason: 'tampered bytes must not verify as the id');
    });
  });

  group('multi-source fetch (work-stealing + resume)', () {
    test('assembles a file from two providers', () async {
      final file = _bytes(800 * 1024, seed: 5); // 25 chunks
      final sha = _sha(file);
      final bus = _Bus();
      final fetchId = await RnsIdentity.generate();
      final fetcherNode = bus.attach((send) => FileTransferNode(
          identity: fetchId, source: const EmptyFileSource(), send: send));
      final records = <ProviderRecord>[];
      for (var i = 0; i < 2; i++) {
        final pid = await RnsIdentity.generate();
        bus.attach((send) => FileTransferNode(
            identity: pid,
            source: MemoryFileSource()..add(file),
            send: send));
        records.add(await ProviderRecord.create(
            providerIdentity: pid, sha256: sha));
      }
      final got = await fetcherNode.node
          .multiSourceFetch(sha, records, timeout: const Duration(seconds: 60));
      expect(got, isNotNull);
      expect(_sha(got!), equals(sha));
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('completes when one provider drops mid-transfer (resume)', () async {
      final file = _bytes(800 * 1024, seed: 6); // 25 chunks
      final sha = _sha(file);
      final bus = _Bus();
      final fetchId = await RnsIdentity.generate();
      final fetcherNode = bus.attach((send) => FileTransferNode(
          identity: fetchId, source: const EmptyFileSource(), send: send));
      // Provider A: healthy, full file. Provider B: dies after serving the
      // manifest + a couple of chunks, so its chunks are requeued to A.
      final records = <ProviderRecord>[];
      final aId = await RnsIdentity.generate();
      bus.attach((send) => FileTransferNode(
          identity: aId, source: MemoryFileSource()..add(file), send: send));
      records.add(await ProviderRecord.create(providerIdentity: aId, sha256: sha));
      final bId = await RnsIdentity.generate();
      bus.attach((send) => FileTransferNode(
          identity: bId, source: _FlakySource(file, 3), send: send));
      records.add(await ProviderRecord.create(providerIdentity: bId, sha256: sha));

      final got = await fetcherNode.node
          .multiSourceFetch(sha, records, timeout: const Duration(seconds: 60));
      expect(got, isNotNull, reason: 'a surviving provider must complete the file');
      expect(_sha(got!), equals(sha));
    }, timeout: const Timeout(Duration(minutes: 2)));
  });
}
