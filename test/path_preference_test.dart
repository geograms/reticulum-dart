/*
 * Path preference — a co-located peer visible over BOTH the LAN and slower
 * media (internet hub, BLE) must be reached over the LAN (fastest medium),
 * regardless of announce arrival order. Locks the speedRank tie-break added
 * with the LAN unicast-data lane.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _FakeIface extends RnsInterface {
  _FakeIface(this._label, {int rank = 2, bool annOnly = false})
      : _rank = rank,
        _annOnly = annOnly;
  final String _label;
  final int _rank;
  final bool _annOnly;
  final List<Uint8List> sent = [];
  @override
  String get label => _label;
  @override
  int get speedRank => _rank;
  @override
  bool get announceOnly => _annOnly;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

// Fresh announce per call (new random hash) — the transport's packet dedup
// drops byte-identical re-ingests, exactly like the live network where each
// announce period produces a new packet.
Future<RnsPacket> _announce(RnsIdentity id) async =>
    RnsAnnounceBuilder.build(id, 'pathpref', const ['peer']);

void main() {
  group('path preference by medium speed', () {
    late RnsTransport t;
    late _FakeIface lan, hub, ble;

    setUp(() {
      t = RnsTransport();
      lan = _FakeIface('lan', rank: 3);
      hub = _FakeIface('tcp:hub', rank: 2);
      ble = _FakeIface('ble', rank: 1);
      t.addInterface(lan);
      t.addInterface(hub);
      t.addInterface(ble);
    });

    test('LAN replaces a hub path (fastest medium wins)', () async {
      final id = await RnsIdentity.generate();
      final a1 = await _announce(id);
      await t.ingest(a1, 'tcp:hub');
      expect(t.pathFor(a1.destHash)!.via, 'tcp:hub');
      await t.ingest(await _announce(id), 'lan');
      expect(t.pathFor(a1.destHash)!.via, 'lan');
    });

    test('a slower medium never displaces the LAN path', () async {
      final id = await RnsIdentity.generate();
      final a1 = await _announce(id);
      await t.ingest(a1, 'lan');
      await t.ingest(await _announce(id), 'tcp:hub');
      expect(t.pathFor(a1.destHash)!.via, 'lan',
          reason: 'hub re-announce must not displace the LAN path');
      await t.ingest(await _announce(id), 'ble');
      expect(t.pathFor(a1.destHash)!.via, 'lan',
          reason: 'BLE re-announce must not displace the LAN path');
    });

    test('LAN replaces BLE at equal hops', () async {
      final id = await RnsIdentity.generate();
      final a1 = await _announce(id);
      await t.ingest(a1, 'ble');
      expect(t.pathFor(a1.destHash)!.via, 'ble');
      await t.ingest(await _announce(id), 'lan');
      expect(t.pathFor(a1.destHash)!.via, 'lan');
    });

    test('same medium: refresh keeps working (equal hops replace)', () async {
      final id = await RnsIdentity.generate();
      final a1 = await _announce(id);
      await t.ingest(a1, 'tcp:hub');
      final first = t.pathFor(a1.destHash)!.updatedMs;
      await Future<void>.delayed(const Duration(milliseconds: 5));
      await t.ingest(await _announce(id), 'tcp:hub');
      expect(t.pathFor(a1.destHash)!.updatedMs, greaterThanOrEqualTo(first));
    });
  });

  _demotionTests();
}

// ── Link-failure path demotion (asymmetric-LAN fallback) ──────────────────
void _demotionTests() {
  group('link-failure path demotion', () {
    late RnsTransport t;
    setUp(() {
      t = RnsTransport();
      t.addInterface(_FakeIface('lan', rank: 3));
      t.addInterface(_FakeIface('tcp:hub', rank: 2));
    });

    test('a failed LAN link lets the hub path win until the penalty lapses',
        () async {
      final id = await RnsIdentity.generate();
      final a1 = await RnsAnnounceBuilder.build(id, 'pathpref', const ['peer']);
      // Learn hub first, then LAN wins by speedRank.
      await t.ingest(a1, 'tcp:hub');
      await t.ingest(
          await RnsAnnounceBuilder.build(id, 'pathpref', const ['peer']), 'lan');
      expect(t.pathFor(a1.destHash)!.via, 'lan');

      // The LAN link keeps failing → demote it.
      t.noteLinkFailure(a1.destHash);
      expect(t.pathFor(a1.destHash), isNull, reason: 'entry dropped to re-resolve');

      // Now both media re-announce. The penalized LAN must NOT reclaim the path
      // over the hub.
      await t.ingest(
          await RnsAnnounceBuilder.build(id, 'pathpref', const ['peer']), 'lan');
      await t.ingest(
          await RnsAnnounceBuilder.build(id, 'pathpref', const ['peer']),
          'tcp:hub');
      expect(t.pathFor(a1.destHash)!.via, 'tcp:hub',
          reason: 'demoted LAN loses to the working hub during the cooldown');
    });

    test('failure with no known path is a no-op (no throw)', () async {
      final id = await RnsIdentity.generate();
      final a = await RnsAnnounceBuilder.build(id, 'pathpref', const ['peer']);
      t.noteLinkFailure(a.destHash); // never learned — must not throw
      expect(t.pathFor(a.destHash), isNull);
    });
  });
}
