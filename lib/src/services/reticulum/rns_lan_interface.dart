/*
 * RNS LAN interface — announce DISCOVERY by broadcast, DATA by unicast.
 *
 * Same-network nodes find each other without a hub by exchanging ANNOUNCE
 * packets over the local subnet broadcast. Data (links, resources, DHT,
 * LXMF — anything) then flows DIRECTLY between the peers as UDP unicast at
 * LAN speed, so two co-located devices never route their traffic through an
 * internet hub just because they also see it.
 *
 * Flood safety (the reason this interface was once announce-only): the
 * transport fans some outbound packets onto every interface. Carrying data
 * as subnet BROADCAST would blast a busy hub\'s transit traffic across the
 * LAN and every node would re-process it. Instead:
 *   - send():   announces -> subnet broadcast (discovery, as before);
 *               everything else -> UNICAST, one copy per announce-known
 *               Aurora peer (bounded, typically 1-3 on a home LAN); with no
 *               known peers data is dropped exactly like the old behavior.
 *   - receive(): announces learn the sender\'s address (peer table, 10 min
 *               TTL) and pass up; unicast data passes up; nothing is
 *               re-broadcast.
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

  /// Announce-known peers: address-key -> (addr, port, last heard). Data is
  /// unicast to these only. Bounded; stale entries age out.
  final Map<String, _LanPeer> _peers = {};
  static const int _peerTtlMs = 10 * 60 * 1000;
  static const int _maxPeers = 16;

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

  /// Local addresses, so our own broadcast loopback never registers us as a
  /// peer (we would unicast every packet to ourselves).
  final Set<String> _selfAddrs = {};

  Future<void> bind() async {
    _broadcastAddr = InternetAddress(broadcastHost);
    final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
    s.broadcastEnabled = true;
    _socket = s;
    try {
      for (final ni in await NetworkInterface.list(
          type: InternetAddressType.IPv4)) {
        for (final a in ni.addresses) {
          _selfAddrs.add(a.address);
        }
      }
    } catch (_) {}
    log?.call('LAN on UDP $port (announce broadcast + unicast data)');
    s.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = s.receive();
      if (dg == null) return;
      final fromSelf = _selfAddrs.contains(dg.address.address);
      if (_isAnnounce(dg.data)) {
        // Discovery: learn the peer\'s address for the unicast data lane.
        if (!fromSelf) _learnPeer(dg.address, dg.port);
      } else if (fromSelf) {
        return; // our own unicast echo (shouldn\'t happen, but cheap guard)
      }
      try {
        onPacket(Uint8List.fromList(dg.data));
      } catch (e) {
        log?.call('onPacket error: $e');
      }
    });
  }

  void _learnPeer(InternetAddress addr, int fromPort) {
    final key = addr.address;
    final known = _peers.containsKey(key);
    _peers[key] = _LanPeer(addr, fromPort == 0 ? port : fromPort,
        DateTime.now().millisecondsSinceEpoch);
    if (!known) log?.call('peer $key joined (\${_peers.length} on LAN)');
    if (_peers.length > _maxPeers) {
      // Evict the stalest.
      String? oldest;
      var oldestMs = 1 << 62;
      for (final e in _peers.entries) {
        if (e.value.lastMs < oldestMs) {
          oldestMs = e.value.lastMs;
          oldest = e.key;
        }
      }
      if (oldest != null) _peers.remove(oldest);
    }
  }

  @override
  void send(Uint8List packetRaw) {
    final s = _socket;
    if (s == null) return;
    if (_isAnnounce(packetRaw)) {
      s.send(packetRaw, _broadcastAddr, port); // discovery, as always
      return;
    }
    // Data: one unicast copy per known LAN peer. Never broadcast; with no
    // known peers this drops the packet — identical to the old behavior.
    if (_peers.isEmpty) return;
    final cutoff = DateTime.now().millisecondsSinceEpoch - _peerTtlMs;
    _peers.removeWhere((_, p) => p.lastMs < cutoff);
    for (final p in _peers.values) {
      s.send(packetRaw, p.addr, p.port);
    }
  }

  Future<void> close() async {
    _socket?.close();
    _socket = null;
  }
}

class _LanPeer {
  final InternetAddress addr;
  final int port;
  final int lastMs;
  _LanPeer(this.addr, this.port, this.lastMs);
}
