/*
 * RNS transport: announce/path table + transport-node forwarding (RNS 1.3.5).
 *
 * Reticulum is NOT a DHT — destinations announce themselves and each node keeps,
 * per destination, the path it last heard the most recent announce on. A
 * TRANSPORT node also rebroadcasts inbound announces onto its other interfaces
 * so destinations on one segment become reachable from another (the bridging
 * that lets BLE / LoRa / LAN segments interconnect).
 *
 * Hop accounting (RNS/Transport.py): a received packet's hop count is +1'd on
 * arrival (the hop just taken). The path table stores that incremented value,
 * and a rebroadcast carries it on the wire as HEADER_2 with transport_type=
 * TRANSPORT and transport_id = this node's (relay) identity hash. The origin's
 * announce signature does not cover hops, so the original announce data is reused
 * verbatim.
 */
import 'dart:math';
import 'dart:typed_data';

import 'rns_announce.dart';
import 'rns_crypto.dart';
import 'rns_identity.dart';
import 'rns_link.dart';
import 'rns_packet.dart';

/// RNS PATHFINDER_M — maximum hops.
const int kRnsMaxHops = 128;

/// A transport interface: something that can send a raw RNS packet, with a
/// stable label so the transport can avoid echoing a packet back out the way it
/// came.
abstract class RnsInterface {
  String get label;
  void send(Uint8List packetRaw);

  /// True for discovery-only interfaces (e.g. the LAN UDP interface) that carry
  /// announces but DROP all data packets. A path learned on such an interface
  /// can never carry a link/DHT/file transfer, so it must not shadow a path
  /// learned on a data-capable interface (the hub). Default false.
  bool get announceOnly => false;

  /// Relative link speed for path preference among equally-capable paths:
  /// a co-located peer reachable over BOTH the LAN and an internet hub (or
  /// BLE) should be reached over the fastest medium. Higher = faster.
  /// 3 = LAN, 2 = TCP/UDP (default), 1 = BLE.
  int get speedRank => 2;

  /// The hardware MTU this interface can carry, used for link MTU discovery
  /// (RNS Interface.HW_MTU). The default [kRnsMtu] means "no discovery" — links
  /// over this interface stay at the 500-byte protocol MTU. Interfaces that can
  /// carry larger frames (TCP) override this to negotiate bigger resource parts.
  int get hardwareMtu => kRnsMtu;

  /// True for low-capacity EDGE interfaces (e.g. BLE) when this node is an
  /// [RnsTransport.edgeBridge]. The bridge propagates announces heard on an edge
  /// UP onto core interfaces, but never re-airs the core (internet) announce
  /// flood back onto an edge — that would saturate BLE and starve APRS. Default
  /// false.
  bool get edge => false;
}

class RnsPathEntry {
  final Uint8List destHash;
  final RnsIdentity identity;
  final Uint8List publicKey;
  Uint8List appData;
  int hops; // RNS convention: received wire hops + 1
  String via; // interface label the announce arrived on
  // Next-hop transport id (16B) when the destination is reachable THROUGH a
  // transport node (the relayer's id from the HEADER_2 announce); null when the
  // destination is a direct neighbour. To send to a transported destination we
  // emit HEADER_2 with transport_type=TRANSPORT and transport_id=[nextHop] so the
  // transport forwards it.
  Uint8List? nextHop;
  int updatedMs;

  RnsPathEntry({
    required this.destHash,
    required this.identity,
    required this.publicKey,
    required this.appData,
    required this.hops,
    required this.via,
    required this.nextHop,
    required this.updatedMs,
  });
}

class RnsTransport {
  final void Function(String msg)? log;

  /// When set, this node acts as a TRANSPORT node and rebroadcasts inbound
  /// announces onto its other interfaces, tagged with [transportId] (16-byte
  /// relay identity hash).
  Uint8List? transportId;

  /// Scoped "edge bridge" relaying (e.g. a phone bridging BLE peers onto the
  /// internet hubs). When true, [_rebroadcast] only propagates announces heard
  /// on an [RnsInterface.edge] interface, and only onto NON-edge (core)
  /// interfaces — so local BLE peers become reachable from the internet, but the
  /// internet announce flood is never re-aired back onto BLE (which would
  /// saturate it and starve APRS that shares the radio). Packet/link forwarding
  /// ([_maybeForward]) is unaffected and bridges both directions. When false
  /// (default) rebroadcast behaves like a normal transport node.
  bool edgeBridge = false;

  final List<RnsInterface> _interfaces = [];
  final Map<String, RnsPathEntry> _paths = {};

  /// LRU cap on the path table. A phone leaf attached to a full transport hub
  /// hears the entire network's announces; without a cap the table grows
  /// unbounded (the old out-of-memory). 2048 is far more than any one device
  /// talks to while keeping memory bounded.
  static const int _maxPaths = 2048;

  // Budget for verifying announces from *new* destinations, so a public hub's
  // network-wide flood can't build an endless crypto backlog on phone hardware.
  // Re-announces of known destinations are exempt (cheap, and keep active paths
  // fresh). Our own overlay's announces are priority-exempt below.
  static const int _annBudgetPerWindow = 1;
  static const int _annBudgetWindowMs = 3000;
  int _annWindowStart = 0;
  int _annCount = 0;
  // Global ceiling on REAL Ed25519 verifications per window, across every
  // announce class — including known-destination re-announces and priority
  // announces, which bypass the new-destination budget above. A re-announce
  // whose app_data changed (uptime fields churn every announce) misses the
  // trustIf fast-path and costs a full verify, so without this ceiling a busy
  // hub's known-dest flood keeps the crypto pipeline saturated forever.
  static const int _verifyBudgetPerWindow = 8;
  int _verifyWindowStart = 0;
  int _verifyCount = 0;

  bool _takeVerifyToken() {
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    if (nowMs - _verifyWindowStart >= _annBudgetWindowMs) {
      _verifyWindowStart = nowMs;
      _verifyCount = 0;
    }
    if (_verifyCount >= _verifyBudgetPerWindow) return false;
    _verifyCount++;
    return true;
  }

  // Announce name_hashes (10-byte, hex) that must NEVER be shed by the budget —
  // our OWN overlay's destinations (e.g. Aurora chat/files/dht/relay). They're
  // rare in the public-hub flood but essential for peer discovery; the host
  // fills this with RnsDestination.nameHash(app, aspects) for each. The name
  // hash is a constant per app+aspects, so one cheap lookup identifies them
  // without verifying the signature.
  final Set<String> priorityAnnounceNames = {};
  // Offset of the 10-byte name_hash in announce data: after the 64-byte pubkey.
  static const int _annPubkeyLen = 64;
  static const int _annNameHashLen = 10;

  bool _isPriorityAnnounce(RnsPacket p) {
    if (priorityAnnounceNames.isEmpty) return false;
    final d = p.data;
    if (d.length < _annPubkeyLen + _annNameHashLen) return false;
    final nh = _hex(Uint8List.sublistView(
        d, _annPubkeyLen, _annPubkeyLen + _annNameHashLen));
    return priorityAnnounceNames.contains(nh);
  }
  final Set<String> _seenPackets = {};
  // Link table for transport forwarding: link_id hex -> the two interfaces the
  // link bridges (created when we forward a LINKREQUEST). Lets us route every
  // subsequent link-addressed packet (proof, link data, resource) both ways.
  final Map<String, _LinkRoute> _linkTable = {};
  static const int _maxLinkRoutes = 4096;
  static const int _linkRouteTtlMs = 3600 * 1000; // 1h idle

  // ── Passive (leaf) mode under CPU pressure ───────────────────────────────
  // Relaying the whole public-hub announce flood (rebroadcasting every inbound
  // announce onto every other interface, plus link/resource transit) is what
  // pegs a phone CPU and ANRs the app. When the inbound announce rate shows the
  // node can't afford that work, it drops to PASSIVE: it stays connected to all
  // hubs and keeps announcing + receiving its OWN traffic (the hubs do the
  // relaying), but stops relaying OTHER nodes' traffic. It auto-resumes when the
  // network quiets. This keeps a constrained device usable without leaving the
  // mesh — exactly the real-world "my CPU can't take it, so go passive" case.
  bool _passive = false;
  bool get passive => _passive;

  /// When true (default), [passive] is managed automatically from the observed
  /// announce load. Set false to pin the mode (manual override / tests).
  bool autoPassive = true;

  /// Force passive on/off (also stops auto-management until re-enabled).
  void setPassive(bool value, {bool auto = false}) {
    autoPassive = auto;
    if (_passive != value) {
      _passive = value;
      log?.call('passive ${value ? 'ON (manual)' : 'OFF (manual)'}');
    }
  }

  // Inbound-announce-rate sampler (the relay-work proxy: relay cost rises with
  // announces/sec × interface count). Sampled even while passive so we can tell
  // when the flood has subsided enough to safely resume relaying. Hysteresis: go
  // passive after a few sustained high-rate seconds, resume after a longer calm.
  static const int _loadHighPerSec = 50; // above → relaying would peg a phone
  static const int _loadLowPerSec = 12;  // below → relaying is affordable again
  static const int _overSecsToPassive = 3;
  static const int _underSecsToActive = 10;
  int _loadWinStartMs = 0;
  int _annInWin = 0;
  int _overSecs = 0;
  int _underSecs = 0;
  double _lastAnnPerSec = 0;

  /// Most recent measured inbound announce rate (announces/second).
  double get announceRatePerSec => _lastAnnPerSec;

  void _accountAnnounceLoad() {
    final now = DateTime.now().millisecondsSinceEpoch;
    if (_loadWinStartMs == 0) _loadWinStartMs = now;
    _annInWin++;
    final elapsed = now - _loadWinStartMs;
    if (elapsed < 1000) return;
    final perSec = _annInWin * 1000 / elapsed;
    _lastAnnPerSec = perSec;
    _loadWinStartMs = now;
    _annInWin = 0;
    if (!autoPassive) return;
    if (perSec >= _loadHighPerSec) {
      _underSecs = 0;
      _overSecs++;
      if (!_passive && _overSecs >= _overSecsToPassive) {
        _passive = true;
        log?.call(
            'passive ON — announce flood ${perSec.round()}/s, shedding relay to save CPU');
      }
    } else if (perSec <= _loadLowPerSec) {
      _overSecs = 0;
      _underSecs++;
      if (_passive && _underSecs >= _underSecsToActive) {
        _passive = false;
        log?.call(
            'passive OFF — announce load ${perSec.round()}/s, resuming relay');
      }
    } else {
      _overSecs = 0;
      _underSecs = 0;
    }
  }

  RnsTransport({this.log, this.transportId});

  int get pathCount => _paths.length;
  Iterable<RnsPathEntry> get paths => _paths.values;
  // A relaying transport node only when it has a relay id AND isn't shedding
  // load. In passive mode it still announces/receives its own traffic.
  bool get isTransportNode => transportId != null && !_passive;

  void addInterface(RnsInterface iface) => _interfaces.add(iface);
  void removeInterface(RnsInterface iface) =>
      _interfaces.removeWhere((i) => identical(i, iface));

  /// Originate a locally-produced packet on every interface (e.g. our own
  /// announce). Inbound relaying uses [ingest]'s rebroadcast instead.
  void sendOnAll(Uint8List raw) {
    for (final i in _interfaces) {
      i.send(raw);
    }
  }

  // The interface label a given link's traffic flows on (link_id hex -> label),
  // learned from inbound link packets. A link is sticky to the path it was
  // established on, so its DATA/parts must go out ONLY there — broadcasting link
  // traffic on every interface multiplies our uplink load (e.g. 5 hubs => 5x),
  // which on a phone saturates the uplink and stalls a large Resource transfer.
  final Map<String, String> _linkIface = {};
  final List<String> _linkIfaceOrder = [];
  static const int _maxLinkIface = 512;

  /// Record that link [linkId] is reachable on interface [via] (called for every
  /// inbound link-addressed packet).
  void noteLinkIface(Uint8List linkId, String via) {
    final k = _hex(linkId);
    final cur = _linkIface[k];
    if (cur == via) return;
    // A link's setup packets (LRPROOF/LRRTT) can arrive on MORE than one
    // interface — the request went out on all of them, so the peer may answer on
    // each. Keep the FASTEST interface, not merely the last one seen: otherwise a
    // slow/flaky hub copy arriving after the good LAN copy would flip subsequent
    // link DATA (GET_FILE, resource) onto the hub and the transfer would stall.
    if (cur != null && _speedRank(cur) > _speedRank(via)) return;
    if (cur == null) {
      _linkIfaceOrder.add(k);
      if (_linkIfaceOrder.length > _maxLinkIface) {
        _linkIface.remove(_linkIfaceOrder.removeAt(0));
      }
    }
    _linkIface[k] = via;
  }

  /// Send a locally-produced packet, routing LINK-addressed traffic on the single
  /// interface that link uses (if known); everything else goes on all interfaces.
  /// This is the right default for file/relay/lxmf link traffic — it keeps a big
  /// Resource transfer from being multiplied across every hub uplink.
  void sendLinkAware(Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p != null) {
      // Established link traffic: stick to the interface that link flows on.
      if (p.destType == RnsDestType.link) {
        final label = _linkIface[_hex(p.destHash)];
        if (label != null) {
          final iface = _ifaceByLabel(label);
          if (iface != null) {
            iface.send(raw);
            return;
          }
        }
      }
      // Transport-addressed (HEADER_2) traffic — e.g. a LINKREQUEST to a remote
      // destination — must go out ONLY on the interface where that dest's path
      // was learned, exactly like reference RNS (Transport.outbound sends on
      // path.receiving_interface). Broadcasting it on every hub emits duplicate
      // copies with the same packet hash; RNS's dedup at intermediate nodes can
      // then drop the copy travelling the good route before it reaches the
      // holder, so the link never establishes even with a valid path.
      if (p.headerType == RnsHeaderType.header2) {
        final path = pathFor(p.destHash);
        if (path != null) {
          final iface = _ifaceByLabel(path.via);
          if (iface != null) {
            iface.send(raw);
            return;
          }
        }
      }
      // A HEADER_1 link REQUEST (destType single) normally goes out on ALL
      // interfaces (below): the handshake must round-trip, and a shared-medium
      // LAN can be ASYMMETRIC (A's subnet broadcasts reach B but not vice-versa
      // — AP broadcast filtering), so pinning to the LAN could black-hole it.
      // EXCEPTION: a top-rank (≥4) interface is a dedicated point-to-point pipe
      // — a WiFi-Direct P2P link — which is symmetric by construction and has no
      // hub fallback to preserve. Pin the request to it so the RESPONDER hears
      // it over that link and confirms the link's large MTU; otherwise the peer
      // accepts a duplicate that arrived over a 500-MTU medium first and the two
      // ends disagree on MTU, stalling the resource transfer.
      if (p.destType == RnsDestType.single) {
        final path = pathFor(p.destHash);
        if (path != null && _speedRank(path.via) >= 4) {
          final iface = _ifaceByLabel(path.via);
          if (iface != null) {
            iface.send(raw);
            return;
          }
        }
      }
    }
    sendOnAll(raw);
  }

  RnsPathEntry? pathFor(Uint8List destHash) => _paths[_hex(destHash)];
  bool hasPath(Uint8List destHash) => _paths.containsKey(_hex(destHash));

  /// The hardware MTU of the interface a packet to [destHash] would leave on —
  /// used by the link initiator to offer a larger link MTU (RNS link MTU
  /// discovery / Transport.next_hop_interface_hw_mtu). Falls back to [kRnsMtu]
  /// when no path/interface is known (i.e. no discovery).
  int nextHopInterfaceHwMtu(Uint8List destHash) {
    final path = pathFor(destHash);
    if (path == null) return kRnsMtu;
    return _ifaceByLabel(path.via)?.hardwareMtu ?? kRnsMtu;
  }

  /// HW MTU of the interface labelled [via] (the one a packet just arrived on) —
  /// used by the responder to cap the link MTU it confirms to what its return
  /// path can carry. Falls back to [kRnsMtu] for unknown labels.
  int hwMtuForVia(String via) => _ifaceByLabel(via)?.hardwareMtu ?? kRnsMtu;

  /// Originate a single connectionless DATA packet addressed to [destHash]
  /// (already-encrypted [data]), routed via our path table: HEADER_2 to the
  /// next-hop transport node if we hold one, else HEADER_1 broadcast for the
  /// directly-attached hub to forward toward the destination. Used for
  /// connectionless app delivery to a SINGLE destination (e.g. a circles
  /// rendezvous join request) WITHOUT a link handshake — one packet, so it
  /// survives an asymmetric inbound far better than a 3-way link setup.
  void sendDataTo(Uint8List destHash, Uint8List data,
      {int context = RnsContext.none}) {
    final path = _paths[_hex(destHash)];
    final toTransport = path?.nextHop != null;
    final pkt = RnsPacket(
      destHash: destHash,
      data: data,
      headerType:
          toTransport ? RnsHeaderType.header2 : RnsHeaderType.header1,
      transportType: toTransport
          ? RnsTransportType.transport
          : RnsTransportType.broadcast,
      destType: RnsDestType.single,
      packetType: RnsPacketType.data,
      context: context,
      transportId: toTransport ? path!.nextHop : null,
    );
    sendOnAll(pkt.pack());
  }

  /// Diagnostic: the routing details of our path to [destHash] (next hop, the
  /// interface we'd forward on, hops, age). Null if we hold no path.
  Map<String, dynamic>? pathInfo(Uint8List destHash) {
    final e = _paths[_hex(destHash)];
    if (e == null) return null;
    return {
      'nextHop': e.nextHop == null ? null : _hex(e.nextHop!),
      'via': e.via,
      'hops': e.hops,
      'ageMs': DateTime.now().millisecondsSinceEpoch - e.updatedMs,
      'identity': _hex(e.identity.hash),
    };
  }

  /// Diagnostic: labels of the live interfaces (the hubs/links we forward on).
  List<String> get interfaceLabels => [for (final i in _interfaces) i.label];

  // ── Path requests (pull path-finding) ───────────────────────────────────
  // The well-known RNS path-request destination: PLAIN "rnstransport.path.request"
  // → truncated_hash(name_hash). Asking this destination for a path is the PULL
  // half of RNS path-finding: a peer (or a hub the target is a local client of)
  // answers with the target's announce (context PATH_RESPONSE), which ingest()
  // learns as an ordinary announce. This reaches a destination whose announce
  // never passively flooded to us (busy/asymmetric public hubs) — the hub the
  // target is directly attached to answers on our direct link.
  static final Uint8List _pathRequestDest = RnsCrypto.truncatedHash(
      RnsDestination.nameHash('rnstransport', ['path', 'request']));
  final Random _rng = Random.secure();

  /// Ask the network for a path to [destHash]. Best-effort, fire-and-forget;
  /// the response arrives asynchronously as a PATH_RESPONSE announce.
  void requestPath(Uint8List destHash) {
    if (_interfaces.isEmpty) return;
    final tag = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      tag[i] = _rng.nextInt(256);
    }
    // transport-enabled form: dest_hash(16) + our_transport_id(16) + tag(16).
    final data = BytesBuilder();
    data.add(destHash);
    data.add(transportId ?? Uint8List(16));
    data.add(tag);
    final pkt = RnsPacket(
      destHash: _pathRequestDest,
      data: data.toBytes(),
      headerType: RnsHeaderType.header1,
      transportType: RnsTransportType.broadcast,
      destType: RnsDestType.plain,
      packetType: RnsPacketType.data,
      context: RnsContext.none,
      hops: 0,
    );
    sendOnAll(pkt.pack());
    log?.call('path request -> ${_hex(destHash)}');
  }

  /// Whether the interface with [label] is announce-only (discovery, no data).
  /// Unknown labels (e.g. a removed interface) are treated as data-capable so a
  /// stale entry is never wrongly preferred or dropped.
  bool _isAnnounceOnly(String label) {
    for (final i in _interfaces) {
      if (i.label == label) return i.announceOnly;
    }
    return false;
  }

  // Fastest data-capable interface we've heard each identity's announces on
  // (identityHex -> interface label). Lets a dest whose own (broadcast) announce
  // was lost still route over the LAN when a SIBLING dest of the same node was
  // heard there — co-located transfer no longer depends on every dest's beacon.
  final Map<String, String> _identityFastVia = {};

  int _speedRank(String label) {
    for (final i in _interfaces) {
      if (i.label == label) return i.speedRank;
    }
    return 2;
  }

  /// Public speed-rank of the interface labelled [label] (2 if unknown).
  int speedRankOf(String label) => _speedRank(label);

  /// A duplicate announce arrived on interface [via]. If we already track this
  /// destination and [via] is a data-capable interface strictly faster than the
  /// path's current via, repoint the path onto it (a WiFi-Direct link winning
  /// over the shared LAN it duplicates). No signature re-verify (identical
  /// signed packet) and no rebroadcast.
  void _maybeUpgradePath(RnsPacket p, String via) {
    if (p.packetType != RnsPacketType.announce) return;
    if (_isAnnounceOnly(via)) return; // can't carry data — never a path
    final key = _hex(p.destHash);
    final existing = _paths[key];
    if (existing == null || existing.via == via) return;
    if (_isAnnounceOnly(existing.via)) return; // handled by the main path logic
    if (_speedRank(via) <= _speedRank(existing.via)) return;
    final nextHop =
        p.headerType == RnsHeaderType.header2 ? p.transportId : null;
    log?.call('path ${key.substring(0, 8)} ${existing.via} -> $via '
        '(rank ${_speedRank(existing.via)}->${_speedRank(via)}, upgrade)');
    _paths.remove(key);
    _paths[key] = RnsPathEntry(
      destHash: existing.destHash,
      identity: existing.identity,
      publicKey: existing.publicKey,
      appData: existing.appData,
      hops: p.hops + 1,
      via: via,
      nextHop: nextHop,
      updatedMs: DateTime.now().millisecondsSinceEpoch,
    );
  }

  /// The next-hop transport for reaching [identity]'s destinations. A peer
  /// announces one destination (e.g. its chat dest), but every destination of
  /// that identity is reached via the same next hop, so we look up by identity.
  /// Returns null when the peer is a direct neighbour (single hop) or unknown.
  Uint8List? nextHopForIdentity(RnsIdentity identity) {
    final want = _hex(identity.hash);
    for (final e in _paths.values) {
      if (_hex(e.identity.hash) == want) return e.nextHop;
    }
    return null;
  }

  /// Ingest an inbound packet that arrived on interface [via]. Validates
  /// announces, updates the path table, and (if a transport node) rebroadcasts
  /// the announce onto the other interfaces. Returns the validated announce or
  /// null.
  Future<RnsAnnounce?> ingest(RnsPacket p, String viaArg) async {
    // Dedup by packet hash (RNS uses the same hashable-part scheme).
    final ph = _hex(p.packetHash());
    if (_seenPackets.contains(ph)) {
      // A node sends the SAME announce packet on all of its interfaces. The
      // first copy to arrive (often a slow shared LAN/hub) sets the path and
      // caches the hash; without this, a later copy on a FASTER interface (a
      // WiFi-Direct P2P link) would be dropped here and the path could never
      // repoint to it. So a duplicate announce may still UPGRADE the path's via
      // to a higher-rank, data-capable interface — no re-verify (same signed
      // packet) and no rebroadcast.
      _maybeUpgradePath(p, viaArg);
      return null;
    }
    _seenPackets.add(ph);
    if (_seenPackets.length > 8192) {
      _seenPackets.remove(_seenPackets.first);
    }

    // As a transport node, forward link/resource traffic that isn't for us —
    // unless we've dropped to passive (leaf) mode to shed CPU load.
    if (transportId != null && !_passive && _maybeForward(p, viaArg)) return null;

    if (p.packetType != RnsPacketType.announce) return null;

    // Sample the inbound announce rate (drives the passive-mode auto-switch).
    // Counted before the flood-shed below so it reflects true load, not what we
    // chose to process.
    _accountAnnounceLoad();

    // Connected to a busy transport hub, a phone leaf hears the WHOLE network's
    // announce stream — hundreds of new destinations a second. Verifying an
    // Ed25519 signature for each on the UI isolate pegs a core and ANRs the app.
    // So budget the verification of *new* destinations over a small window;
    // re-announces of destinations we already track are cheap (see trustIf) and
    // never throttled, so paths we actually use keep refreshing. A dropped new
    // announce costs nothing — that destination re-announces periodically and
    // outbound traffic reaches the hub regardless.
    final destKey = _hex(p.destHash);
    // Exempt our own overlay's announces from the flood budget — otherwise the
    // rare Aurora announces get shed amid hundreds of foreign ones a second and
    // nodes never learn each other's routes (no media fetch, no FEED backfill).
    if (!_paths.containsKey(destKey) &&
        !_isPriorityAnnounce(p) &&
        p.context != RnsContext.pathResponse) {
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      if (nowMs - _annWindowStart >= _annBudgetWindowMs) {
        _annWindowStart = nowMs;
        _annCount = 0;
      }
      if (_annCount >= _annBudgetPerWindow) return null; // shed the flood
      _annCount++;
    }

    // Skip re-verifying an unchanged re-announce of a destination we already
    // verified (same key + app_data) — the common case once the table is warm.
    bool trusted(Uint8List dh, Uint8List pk, Uint8List ad) {
      final e = _paths[_hex(dh)];
      return e != null && _eq(e.publicKey, pk) && _eq(e.appData, ad);
    }

    // Anything that will need REAL crypto (trust fast-path miss) draws from the
    // global verify budget — known-dest re-announces with churned app_data and
    // priority announces included. Exhausted budget = shed the packet; the
    // destination re-announces periodically, nothing is lost but freshness.
    final needsCrypto = !wouldTrustAnnounce(p, trusted);
    if (needsCrypto && !_takeVerifyToken()) return null;

    final ann = await validateAnnounce(p, trustIf: trusted);
    if (ann == null) return null;

    var pathHops = p.hops + 1; // hop just taken to reach us
    // If the announce arrived relayed (HEADER_2), the relayer's id is the next
    // hop toward this destination; a direct (HEADER_1) announce is a neighbour.
    var nextHop =
        p.headerType == RnsHeaderType.header2 ? p.transportId : null;
    var via = viaArg;
    // Identity-level LAN reachability. A node's per-destination announces ride
    // unreliable Wi-Fi BROADCAST, so this specific dest's LAN announce may be
    // lost while ANOTHER of the same node's dests (chat/lxmf) was heard over the
    // LAN — leaving this dest stuck on a slow hub path even though the node is a
    // direct LAN neighbour. If we've heard THIS identity over a fast direct
    // medium, treat this dest as reachable there too: a direct 1-hop path on
    // that interface (the LAN peer table already knows the node's address to
    // unicast to). This is what makes co-located transfer use the LAN reliably
    // instead of depending on every single dest's broadcast landing.
    final idHex = _hex(ann.identity.hash);
    final fast = _identityFastVia[idHex];
    if (fast != null &&
        _speedRank(fast) > _speedRank(via) &&
        _ifaceByLabel(fast) != null) {
      via = fast;
      nextHop = null;
      pathHops = 1;
    }
    // Record the fastest data-capable interface we've heard this identity on, so
    // later announces of its OTHER dests can be upgraded to it (above). When it
    // gets FASTER, proactively upgrade EVERY already-known path of this identity
    // to that interface right now — otherwise a sibling dest whose own (rare,
    // broadcast) announce already landed on the hub would stay stuck there until
    // its next announce, and those are minutes apart / often dropped.
    if (!_isAnnounceOnly(viaArg)) {
      final cur = _identityFastVia[idHex];
      if (cur == null || _speedRank(viaArg) > _speedRank(cur)) {
        _identityFastVia[idHex] = viaArg;
        for (final e in _paths.values) {
          if (_hex(e.identity.hash) == idHex &&
              _speedRank(viaArg) > _speedRank(e.via)) {
            e.via = viaArg;
            e.nextHop = null;
            e.hops = 1;
            e.updatedMs = DateTime.now().millisecondsSinceEpoch;
          }
        }
      }
    }
    final key = _hex(ann.destHash);
    final existing = _paths[key];
    // Path preference. A path's usefulness for DATA depends on whether the
    // interface it was heard on can carry data: the LAN UDP interface is
    // announce-only (it drops all non-announce packets), so a path learned there
    // can never carry a link/DHT/file transfer. Such a path must NOT shadow a
    // data-capable (hub/TCP) path even though the LAN announce is fewer hops —
    // that shadowing made every link to a co-located peer time out. Rules:
    //   1. a data-capable ingest always replaces an announce-only entry (any hops);
    //   2. an announce-only ingest never overwrites a data-capable entry;
    //   3. within the same capability class, prefer fewer/equal hops (LRU refresh).
    final viaAnnounceOnly = _isAnnounceOnly(via);
    final existingAnnounceOnly =
        existing != null && _isAnnounceOnly(existing.via);
    final bool replace;
    if (existing == null) {
      replace = true;
    } else if (viaAnnounceOnly && !existingAnnounceOnly) {
      replace = false;
    } else if (!viaAnnounceOnly && existingAnnounceOnly) {
      replace = true;
    } else {
      // Same capability class: prefer the faster medium first (a direct LAN
      // path beats the internet hub AND BLE for a co-located peer), then
      // fewer/equal hops (equal = LRU refresh of the same-quality path). A via
      // that recently FAILED a link handshake for this dest is penalized to
      // rank 0 for a cooldown, so a silently one-way medium (asymmetric-LAN AP
      // client isolation: announces heard but our packets never reach the peer)
      // stops shadowing a working slower path (the hub) — link-failure fallback.
      final newRank = _speedRank(via);
      final oldRank = _speedRank(existing.via);
      if (newRank != oldRank) {
        replace = newRank > oldRank;
      } else {
        replace = pathHops <= existing.hops;
      }
    }
    if (replace) {
      if (existing != null && existing.via != via) {
        log?.call('path ${_hex(ann.destHash).substring(0, 8)} '
            '${existing.via} -> $via (rank ${_speedRank(existing.via)}'
            '->${_speedRank(via)}, hops ${existing.hops}->$pathHops)');
      }
      // Re-insert at the tail so recently-heard destinations are youngest —
      // the table is an LRU bounded by [_maxPaths] (below) so the network-wide
      // announce flood can't grow it without bound (the old OOM).
      _paths.remove(key);
      _paths[key] = RnsPathEntry(
        destHash: ann.destHash,
        identity: ann.identity,
        publicKey: ann.publicKey,
        appData: ann.appData,
        hops: pathHops,
        via: via,
        nextHop: nextHop,
        updatedMs: DateTime.now().millisecondsSinceEpoch,
      );
      // Evict the oldest entries past the cap (insertion order = age).
      while (_paths.length > _maxPaths) {
        _paths.remove(_paths.keys.first);
      }
    }

    // Relay the announce onward only as an active transport node. In passive
    // mode we still learned the path above and return the announce for local
    // delivery, but we don't carry the network's flood on our back.
    if (!_passive) _rebroadcast(p, ann, pathHops, via);
    return ann;
  }

  /// Transport-node forwarding of non-announce packets. Returns true if the
  /// packet was forwarded (i.e. it was transit traffic, not for this node):
  ///   - destType==LINK with a tracked route -> forward to the other interface
  ///     (proof, link data, resource — both directions);
  ///   - HEADER_2 addressed to us (transport_id==ours) -> forward toward the
  ///     destination's path next hop, and (for a LINKREQUEST) remember the link
  ///     so its reverse + data packets route back.
  bool _maybeForward(RnsPacket p, String via) {
    final myId = transportId;
    if (myId == null) return false;
    if (p.hops >= kRnsMaxHops) return false;

    // 1) A packet addressed to a link we bridge.
    if (p.destType == RnsDestType.link) {
      final route = _linkTable[_hex(p.destHash)];
      if (route == null) return false;
      final out = route.other(via);
      if (out == null) return false;
      route.touch();
      out.send(_reframeLink(p).pack());
      return true;
    }

    // 2) A transport-addressed packet whose next hop is us.
    if (p.headerType == RnsHeaderType.header2 &&
        p.transportId != null &&
        _eq(p.transportId!, myId) &&
        p.transportType == RnsTransportType.transport) {
      final path = _paths[_hex(p.destHash)];
      if (path == null) return false; // no route to the destination
      final outIface = _ifaceByLabel(path.via);
      if (outIface == null) return false;

      if (p.packetType == RnsPacketType.linkRequest) {
        final inIface = _ifaceByLabel(via);
        if (inIface != null) {
          _pruneLinkRoutes();
          _linkTable[_hex(RnsLink.linkIdFromRequest(p))] =
              _LinkRoute(inIface, outIface);
        }
      }
      outIface.send(_forwardToward(p, path).pack());
      return true;
    }
    return false;
  }

  // Forward a dest-addressed packet one hop toward [path]. If the destination is
  // a direct neighbour of the next node (path.nextHop == null) send HEADER_1
  // (consume the transport id); otherwise keep transport-addressing to the next
  // transport. hops is incremented.
  RnsPacket _forwardToward(RnsPacket p, RnsPathEntry path) {
    final toTransport = path.nextHop != null;
    return RnsPacket(
      destHash: p.destHash,
      data: p.data,
      headerType:
          toTransport ? RnsHeaderType.header2 : RnsHeaderType.header1,
      transportType: toTransport
          ? RnsTransportType.transport
          : RnsTransportType.broadcast,
      destType: p.destType,
      packetType: p.packetType,
      context: p.context,
      contextFlag: p.contextFlag,
      transportId: toTransport ? path.nextHop : null,
      hops: p.hops + 1,
    );
  }

  // Forward a link-addressed packet to the opposite side of the bridge. The next
  // node is a direct neighbour here (leaf-hub-leaf), so HEADER_1 by link_id; the
  // endpoint matches on the link_id regardless of header form.
  RnsPacket _reframeLink(RnsPacket p) => RnsPacket(
        destHash: p.destHash, // = link_id
        data: p.data,
        headerType: RnsHeaderType.header1,
        transportType: RnsTransportType.broadcast,
        destType: RnsDestType.link,
        packetType: p.packetType,
        context: p.context,
        contextFlag: p.contextFlag,
        hops: p.hops + 1,
      );

  RnsInterface? _ifaceByLabel(String label) {
    for (final i in _interfaces) {
      if (i.label == label) return i;
    }
    return null;
  }

  void _pruneLinkRoutes() {
    final now = DateTime.now().millisecondsSinceEpoch;
    _linkTable.removeWhere((_, r) => now - r.lastMs > _linkRouteTtlMs);
    while (_linkTable.length >= _maxLinkRoutes) {
      _linkTable.remove(_linkTable.keys.first);
    }
  }

  static bool _eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  // Rebroadcast an announce onto every interface except the one it arrived on.
  void _rebroadcast(RnsPacket p, RnsAnnounce ann, int pathHops, String via) {
    final tid = transportId;
    if (tid == null) return;
    if (pathHops >= kRnsMaxHops) return;
    var others = _interfaces.where((i) => i.label != via);
    if (edgeBridge) {
      // Only carry announces heard on an edge (e.g. BLE local peers) and only
      // onto core interfaces — never re-air the internet flood onto BLE, and
      // never loop a hub announce across other hub uplinks.
      final viaIface = _ifaceByLabel(via);
      if (viaIface == null || !viaIface.edge) return;
      others = others.where((i) => !i.edge);
    }
    final targets = others.toList();
    if (targets.isEmpty) return;

    final relay = RnsPacket(
      destHash: ann.destHash,
      data: p.data,
      headerType: RnsHeaderType.header2,
      transportType: RnsTransportType.transport,
      destType: RnsDestType.single,
      packetType: RnsPacketType.announce,
      context: p.context,
      contextFlag: p.contextFlag,
      transportId: tid,
      hops: pathHops,
    );
    final raw = relay.pack();
    for (final iface in targets) {
      iface.send(raw);
      log?.call(
          'rebroadcast ${_hex(ann.destHash)} -> ${iface.label} hops=$pathHops');
    }
  }

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

/// A bridged link: the two interfaces a transit link's packets route between.
class _LinkRoute {
  final RnsInterface a;
  final RnsInterface b;
  int lastMs;
  _LinkRoute(this.a, this.b) : lastMs = DateTime.now().millisecondsSinceEpoch;

  /// The interface opposite to the one a packet arrived on ([viaLabel]).
  RnsInterface? other(String viaLabel) {
    if (viaLabel == a.label) return b;
    if (viaLabel == b.label) return a;
    return null;
  }

  void touch() => lastMs = DateTime.now().millisecondsSinceEpoch;
}
