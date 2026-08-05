// Which medium an outgoing RNS packet takes over BLE.
//
// Two phones with nothing but Bluetooth between them lost about half of every
// message they sent: each one fitted the advert cap, so it was aired once as a
// connectionless BLE advert — unacknowledged, never retransmitted, and heard
// only if the peer's scanner happened to be listening in that window. The link
// that was already open between them, acked and flow-controlled, carried
// nothing at all.
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/reticulum/rns_ble_interface.dart';

/// Packet type lives in the low two bits of the header byte.
Uint8List packet(int len, {bool announce = false}) {
  final p = Uint8List(len);
  p[0] = announce ? 0x01 : 0x00;
  for (var i = 1; i < len; i++) {
    p[i] = i & 0xFF;
  }
  return p;
}

class FakeRadio implements RnsBleRadio {
  FakeRadio({this.cap = 250, this.linkUp = false, this.unicastOk = true});

  final int cap;
  bool linkUp;
  bool unicastOk;

  final List<Uint8List> broadcasts = [];
  final List<Uint8List> unicasts = [];

  @override
  int get broadcastCap => cap;

  @override
  bool get hasLink => linkUp;

  @override
  void broadcast(Uint8List frame) => broadcasts.add(frame);

  @override
  bool unicast(Uint8List frame) {
    if (!unicastOk) return false;
    unicasts.add(frame);
    return true;
  }

  @override
  void onReceive(void Function(Uint8List frame) handler) {}
}

void main() {
  test('with a link up, an addressed packet takes the link', () {
    final radio = FakeRadio(linkUp: true);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100));
    expect(radio.unicasts.length, 1);
    expect(radio.broadcasts, isEmpty); // this is the bug that lost messages
  });

  test('an announce always broadcasts, link or no link', () {
    final radio = FakeRadio(linkUp: true);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100, announce: true));
    expect(radio.broadcasts.length, 1);
    expect(radio.unicasts, isEmpty); // every device in range wants an announce
  });

  test('with no link, a packet that fits still broadcasts', () {
    final radio = FakeRadio();
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100));
    expect(radio.broadcasts.length, 1);
    expect(radio.unicasts, isEmpty);
  });

  test('an over-cap packet goes point-to-point even with no link', () {
    final radio = FakeRadio(cap: 80);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(300));
    expect(radio.unicasts.length, 1);
    expect(radio.broadcasts, isEmpty);
  });

  // A link the radio reports but cannot actually use must not swallow the
  // packet: falling through to the broadcast medium is what keeps a message
  // moving while a link is half-open.
  test('a refused link send falls back to broadcast', () {
    final radio = FakeRadio(linkUp: true, unicastOk: false);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100));
    expect(radio.broadcasts.length, 1);
  });

  test('an over-cap packet with no usable path is dropped, not truncated', () {
    final radio = FakeRadio(cap: 80, unicastOk: false);
    final iface = RnsBleInterface(radio: radio, onPacket: (_) {});
    iface.send(packet(300));
    expect(radio.broadcasts, isEmpty);
    expect(radio.unicasts, isEmpty);
    expect(iface.droppedCount, 1);
  });

  test('counters separate the two media', () {
    final radio = FakeRadio(linkUp: true);
    final iface = RnsBleInterface(radio: radio, onPacket: (_) {});
    iface.send(packet(100)); // link
    iface.send(packet(100, announce: true)); // broadcast
    expect(iface.unicastCount, 1);
    expect(iface.broadcastCount, 1);
  });
}
