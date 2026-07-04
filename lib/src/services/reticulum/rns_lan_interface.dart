/*
 * RNS LAN interface — a subnet-broadcast shared medium (announces AND data).
 *
 * Same-network nodes find each other without a hub by exchanging ANNOUNCE
 * packets over the local subnet broadcast, and then their DATA (links,
 * resources, DHT, LXMF — anything) flows over the same LAN at LAN speed, so two
 * co-located devices never route their traffic through an internet hub just
 * because they also see it.
 *
 * This interface was once announce-only for flood safety: a TRANSPORT node
 * relaying a busy hub's transit onto the LAN as broadcast would peg every
 * node's CPU. A leaf node (edge-bridge off) only ever emits its own low-rate
 * link traffic, so carrying data here is safe and bounded. Behaviour:
 *   - send():   ONE subnet broadcast for everything (announces AND data),
 *               like reference RNS shared-medium interfaces — the medium is a
 *               broadcast bus and RNS dedup + addressing decide who keeps each
 *               packet. (A prior per-peer unicast optimization black-holed
 *               link replies and hung every fetch on 'handshake failed'.)
 *   - receive(): passes every packet up; our own broadcast echo is dropped.
 * One raw RNS packet per UDP datagram.
 */
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'rns_packet.dart';
import 'rns_transport.dart';

class RnsLanInterface implements RnsInterface {
  @override
  final String label;

  // Data-capable since the unicast lane exists; announce-only no more.
  @override
  bool get announceOnly => false;
  @override
  bool get edge => false;
  // LAN Ethernet/WiFi: same HW MTU the reference RNS uses for UDP (1064) so
  // links negotiated over the LAN carry ~2x the protocol SDU.
  @override
  int get hardwareMtu => 1064;
  // Fastest medium we have — beats hub TCP and BLE for co-located peers.
  @override
  int get speedRank => 3;

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

  /// Our own IPv4 addresses, so our broadcast loopback (which we also receive)
  /// is never re-processed as if it came from a peer.
  final Set<String> _selfAddrs = {};

  /// Subnet-DIRECTED broadcast addresses (x.y.z.255 for each local /24), sent
  /// IN ADDITION to the limited 255.255.255.255 — many Android/Wi-Fi setups
  /// silently drop the limited broadcast (asymmetrically, per device) while
  /// forwarding the subnet-directed one, which black-holed one direction of the
  /// LAN and hung co-located fetches. Belt and suspenders: send to both.
  final List<InternetAddress> _directedBcast = [];

  Future<void> bind() async {
    _broadcastAddr = InternetAddress(broadcastHost);
    final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
    s.broadcastEnabled = true;
    _socket = s;
    try {
      for (final ni in await NetworkInterface.list(
          type: InternetAddressType.IPv4)) {
        for (final a in ni.addresses) {
          if (a.isLoopback) continue;
          _selfAddrs.add(a.address);
          // Assume a /24 (the near-universal home-LAN mask; Dart's
          // NetworkInterface exposes no netmask) → x.y.z.255.
          final parts = a.address.split('.');
          if (parts.length == 4) {
            final directed = '${parts[0]}.${parts[1]}.${parts[2]}.255';
            if (!_directedBcast.any((d) => d.address == directed)) {
              _directedBcast.add(InternetAddress(directed));
            }
          }
        }
      }
    } catch (_) {}
    log?.call('LAN on UDP $port (broadcast + ${_directedBcast.length} '
        'subnet-directed, announces + data)');
    s.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = s.receive();
      if (dg == null) return;
      // Drop our own broadcast echo (we receive what we send). An announce from
      // self is harmless (the transport ignores it), but data would be
      // re-processed, so gate on the source being one of our addresses.
      if (_selfAddrs.contains(dg.address.address) && !_isAnnounce(dg.data)) {
        return;
      }
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
    // Everything — announces AND data — goes out as ONE subnet broadcast, the
    // way reference RNS shared-medium interfaces (UDP/Auto) work: the medium IS
    // a broadcast bus, and RNS's own packet dedup + destination addressing sort
    // out who keeps each packet. An earlier per-peer UNICAST optimization here
    // silently black-holed link traffic — a link's reply (LRPROOF/LRRTT) is
    // addressed to the link id and routed back on THIS interface, but the
    // unicast target/port could be stale or wrong, so the proof never reached
    // the initiator and every file/folder fetch hung on 'handshake attempt N
    // failed'. Broadcast is loss-free of that failure mode. The flood the
    // announce-only design once guarded against is a TRANSPORT node relaying a
    // busy hub's transit onto the LAN; a leaf node (edge-bridge off) only emits
    // its own low-rate link traffic, and a home LAN has a handful of nodes, so
    // the cost is bounded. Our own broadcast loopback is dropped on receive.
    // Send to BOTH the limited broadcast and every subnet-directed address, so
    // a peer whose Wi-Fi drops one form still receives via the other.
    s.send(packetRaw, _broadcastAddr, port);
    for (final d in _directedBcast) {
      s.send(packetRaw, d, port);
    }
  }

  Future<void> close() async {
    _socket?.close();
    _socket = null;
  }
}

