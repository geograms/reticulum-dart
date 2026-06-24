/*
 * RNS LAN auto-peering interface — DISCOVERY ONLY.
 *
 * Same-network nodes find each other without a hub by exchanging ANNOUNCE
 * packets over the local subnet broadcast. This interface deliberately carries
 * ONLY announces, in BOTH directions:
 *   - send():   broadcasts announce packets; drops everything else.
 *   - receive(): delivers only announces up the stack; drops everything else.
 *
 * Why: the transport fans every outbound packet out on ALL interfaces
 * (sendOnAll). If this interface also carried link/resource/transit DATA, a
 * node forwarding a busy hub's traffic would blast all of it onto the LAN (and
 * re-process inbound copies), pegging the CPU. Restricting it to announces makes
 * it a cheap discovery beacon; once peers know each other, their actual data
 * rides the normal (TCP hub) path. One raw RNS packet per UDP datagram.
 */
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'rns_packet.dart';
import 'rns_transport.dart';

class RnsLanInterface implements RnsInterface {
  @override
  final String label;

  // Discovery-only: carries announces, drops all data. So a path learned here
  // must never shadow a data-capable (hub) path (see RnsTransport.ingest).
  @override
  bool get announceOnly => true;
  // Announce-only; never carries a link, so MTU discovery is irrelevant.
  @override
  int get hardwareMtu => kRnsMtu;
  final int port; // shared listen + send port (all Aurora nodes use the same)
  final String broadcastHost;
  final void Function(Uint8List packetRaw) onPacket;
  final void Function(String msg)? log;

  RawDatagramSocket? _socket;
  late final InternetAddress _broadcastAddr;

  RnsLanInterface({
    required this.port,
    required this.onPacket,
    this.broadcastHost = '255.255.255.255',
    this.log,
    String? label,
  }) : label = label ?? 'lan';

  // Cheap announce test straight off the header (flags & 0x03) — no full parse.
  static bool _isAnnounce(Uint8List raw) =>
      raw.isNotEmpty && (raw[0] & 0x03) == RnsPacketType.announce;

  Future<void> bind() async {
    _broadcastAddr = InternetAddress(broadcastHost);
    final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
    s.broadcastEnabled = true;
    _socket = s;
    log?.call('LAN discovery on UDP $port (announce-only)');
    s.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = s.receive();
      if (dg == null) return;
      // Discovery only: deliver announces (incl. our own loopback, which the
      // transport harmlessly ignores); drop any data so a misbehaving/old peer
      // can't make us process its traffic.
      if (!_isAnnounce(dg.data)) return;
      try {
        onPacket(Uint8List.fromList(dg.data));
      } catch (e) {
        log?.call('onPacket error: $e');
      }
    });
  }

  @override
  void send(Uint8List packetRaw) {
    final s = _socket;
    if (s == null) return;
    // Only announces ride the LAN; data goes over the normal (hub) path.
    if (!_isAnnounce(packetRaw)) return;
    s.send(packetRaw, _broadcastAddr, port);
  }

  Future<void> close() async {
    _socket?.close();
    _socket = null;
  }
}
