/*
 * LxmfRouter — LXMF DIRECT (over-link) delivery on the Dart Reticulum stack.
 *
 * Registers this node's LXMF "delivery" destination (Destination(identity, IN,
 * SINGLE, 'lxmf', 'delivery')). Outbound: open a Link to the recipient's delivery
 * destination and send the packed LXMessage — as a single link packet if it fits,
 * else as an RNS Resource. Inbound: accept the link, receive the packet/resource,
 * unpack + verify the message (resolving the sender's identity from the path
 * table), and hand it to [onMessage].
 *
 * Transport-agnostic like FileTransferNode: the owner supplies [send] (e.g.
 * transport.sendOnAll), [nextHopFor] (transport addressing for routed peers), and
 * [identityForDest] (resolve an identity from a destination hash, via the path
 * table). Opportunistic single-packet + propagation-node delivery are follow-ups.
 */
import 'dart:async';
import 'dart:typed_data';

import '../rns_crypto.dart';
import '../rns_identity.dart';
import '../rns_link.dart';
import '../rns_packet.dart';
import '../rns_resource.dart';
import '../rns_resource_receiver.dart';
import 'lxmf.dart';
import 'lxmf_message.dart';
import 'lxmf_msgpack.dart';

// Max LXMF packed bytes we send as a single link packet (else use a Resource).
// One link DATA packet's plaintext budget is ~400B after header + token overhead.
const int _linkPacketMax = 360;

class _LxIn {
  final RnsLink link;
  RnsResourceReceiver? rx;
  _LxIn(this.link);
}

class _LxOut {
  final RnsLink link;
  final Uint8List packed;
  final Completer<bool> done;
  RnsResourceSender? sender;
  bool sent = false;
  _LxOut(this.link, this.packed, this.done);
}

class LxmfRouter {
  final RnsIdentity identity;
  final void Function(Uint8List raw) send;
  final Uint8List? Function(RnsIdentity peer)? nextHopFor;
  final RnsIdentity? Function(Uint8List destHash)? identityForDest;
  void Function(LxmfMessage message)? onMessage;
  final void Function(String msg)? log;
  /// Pull a path to [destHash] (RNS path request). Used to resolve the source
  /// identity of an inbound message when we never heard the sender's announce.
  final void Function(Uint8List destHash)? requestPath;

  /// Predicate consulted when an inbound message's source identity can't be
  /// resolved (we never heard its announce, so the LXMF-layer signature can't be
  /// checked). If it returns true the message is delivered anyway — for payloads
  /// that carry their OWN application-layer authentication (e.g. wapp datagrams
  /// signed inside the field), LXMF-layer source verification is redundant and
  /// must not block delivery on asymmetric/quiet hubs. Default: drop.
  final bool Function(LxmfMessage message)? acceptUnverified;

  late final Uint8List deliveryDestHash =
      RnsDestination.hash(identity, kLxmfApp, kLxmfDeliveryAspects);

  final Map<String, _LxIn> _in = {};
  final Map<String, _LxOut> _out = {};

  // ── Store-and-forward (cooperative peer mailbox) ─────────────────────────
  // Every node is a propagation node for its peers: a message we couldn't
  // deliver DIRECTLY is held here keyed by the recipient's delivery-dest hash,
  // and served when that recipient PULLS it over a link it initiates. This
  // sidesteps an unreachable/asymmetric inbound (the recipient reaches out, so
  // it works even when nothing can be pushed to it).
  /// Our propagation destination (Destination(id, IN, SINGLE, lxmf, propagation)).
  late final Uint8List propagationDestHash =
      RnsDestination.hash(identity, kLxmfApp, kLxmfPropagationAspects);
  final Map<String, List<Uint8List>> _mailbox = {}; // recipientHex -> [packed]
  final Map<String, _PropIn> _propIn = {};
  final Map<String, _PropOut> _propOut = {};
  // Link contexts for the sync protocol (Aurora<->Aurora; outside RNS-reserved).
  // The held-message batch itself rides a standard RNS resource over the link.
  static const int _ctxSyncReq = 0x10; // initiator -> responder: "messages for me"
  static const int _ctxSyncMsg = 0x11; // responder -> initiator: ONE held message
  static const int _ctxSyncEnd = 0x12; // responder -> initiator: end of batch
  static const int _ctxSyncAck = 0x13; // initiator -> responder: got them, drop mailbox

  // Stable identity of a message's CONTENT, independent of when it was sent.
  // The LXMF hash/signature fold in the timestamp, so a sender that re-sends the
  // SAME logical message (e.g. a circle owner replaying history every tick) makes
  // a new envelope each time. Dedup on (dest, source, title, content, fields)
  // instead, so the mailbox holds one copy per distinct message — otherwise it
  // fills with hundreds of near-identical envelopes and the pull batch fails.
  String _contentKey(LxmfMessage m) => _hex(RnsCrypto.fullHash([
        ...m.destinationHash,
        ...m.sourceHash,
        ...m.title,
        ...m.content,
        ...msgpackEncode(m.fields),
      ]));

  final Map<String, Set<String>> _mailboxKeys = {}; // recipientHex -> contentKeys

  void _storeForRelay(LxmfMessage m) {
    final k = _hex(m.destinationHash);
    final box = _mailbox[k] ??= [];
    final keys = _mailboxKeys[k] ??= {};
    final ck = _contentKey(m);
    if (keys.contains(ck)) return; // already holding this logical message
    keys.add(ck);
    box.add(m.packed);
    while (box.length > 256) {
      final dropped = box.removeAt(0);
      final dk = _contentKey(LxmfMessage.unpack(dropped) ?? m);
      keys.remove(dk);
    }
    log?.call('lxmf: stored message for relay to ${k.substring(0, 8)} '
        '(${box.length} held)');
  }

  LxmfRouter({
    required this.identity,
    required this.send,
    this.nextHopFor,
    this.identityForDest,
    this.onMessage,
    this.log,
    this.requestPath,
    this.acceptUnverified,
  });

  /// Feed an inbound packet; true if it was an LXMF link/delivery packet.
  Future<bool> handlePacket(RnsPacket p) async {
    if (p.packetType == RnsPacketType.linkRequest &&
        RnsCrypto.constantTimeEquals(p.destHash, deliveryDestHash)) {
      await _accept(p);
      return true;
    }
    if (p.packetType == RnsPacketType.linkRequest &&
        RnsCrypto.constantTimeEquals(p.destHash, propagationDestHash)) {
      await _acceptProp(p);
      return true;
    }
    if (p.destType == RnsDestType.link) {
      final id = _hex(p.destHash);
      final i = _in[id];
      if (i != null) {
        await _onIn(i, p);
        return true;
      }
      final o = _out[id];
      if (o != null) {
        await _onOut(o, p);
        return true;
      }
      final pi = _propIn[id];
      if (pi != null) {
        await _onPropIn(pi, p);
        return true;
      }
      final po = _propOut[id];
      if (po != null) {
        await _onPropOut(po, p);
        return true;
      }
    }
    return false;
  }

  /// Send [message] to its destination over a Reticulum link. Returns true once
  /// it's been delivered to the link (packet) or proven (resource).
  Future<bool> send_(
    LxmfMessage message, {
    Duration timeout = const Duration(seconds: 30),
  }) async {
    // Hold the message for relay IMMEDIATELY (not only after a ~30s direct-push
    // timeout): a recipient with an unreachable/asymmetric inbound can then PULL
    // it on its next sync without waiting for our push to time out. On confirmed
    // direct delivery we drop the held copy; otherwise it stays for the pull. The
    // recipient dedups, so a brief double-delivery window is harmless.
    _storeForRelay(message);
    final rid = identityForDest?.call(message.destinationHash);
    if (rid == null) {
      log?.call('lxmf: no path/identity for destination — held for relay');
      return false;
    }
    final link =
        await RnsLink.initiator(rid, kLxmfApp, kLxmfDeliveryAspects);
    link.nextHop = nextHopFor?.call(rid);
    final reqPkt = link.buildRequest();
    final entry = _LxOut(link, message.packed, Completer<bool>());
    final id = _hex(link.linkId!);
    _out[id] = entry;
    send(reqPkt.pack());
    final ok = await entry.done.future
        .timeout(timeout, onTimeout: () => false);
    _out.remove(id);
    if (ok) _removeFromRelay(message); // direct delivery confirmed → drop held copy
    return ok;
  }

  /// Drop a held copy of [m] (by content key) once it's been delivered directly.
  void _removeFromRelay(LxmfMessage m) {
    final k = _hex(m.destinationHash);
    final box = _mailbox[k];
    final keys = _mailboxKeys[k];
    if (box == null || keys == null) return;
    final ck = _contentKey(m);
    if (!keys.remove(ck)) return;
    box.removeWhere((p) => _contentKey(LxmfMessage.unpack(p) ?? m) == ck);
    if (box.isEmpty) {
      _mailbox.remove(k);
      _mailboxKeys.remove(k);
    }
  }

  // ── Inbound (responder) ────────────────────────────────────────────────────
  Future<void> _accept(RnsPacket request) async {
    try {
      final link = await RnsLink.responder(identity, request);
      _in[_hex(link.linkId!)] = _LxIn(link);
      send((await link.buildProof()).pack());
    } catch (e) {
      log?.call('lxmf: accept link failed: $e');
    }
  }

  Future<void> _onIn(_LxIn e, RnsPacket p) async {
    if (e.link.status != RnsLinkStatus.active && p.context == RnsContext.lrrtt) {
      e.link.handleRtt(p);
      return;
    }
    switch (p.context) {
      case RnsContext.none:
        _deliver(e.link.decrypt(p)); // a single-packet message
        break;
      case RnsContext.resourceAdv:
      case RnsContext.resourceHmu:
      case RnsContext.resource:
        final rx = e.rx ??= RnsResourceReceiver(e.link);
        for (final pkt in rx.handle(p)) {
          send(pkt.pack());
        }
        if (rx.complete) {
          _deliver(rx.payload!);
          e.rx = null;
        } else if (rx.error != null) {
          e.rx = null;
        }
        break;
      default:
        break;
    }
  }

  Future<void> _deliver(Uint8List packed) async {
    final m = LxmfMessage.unpack(packed);
    if (m == null) {
      log?.call('lxmf: dropped undecodable message');
      return;
    }
    var src = identityForDest?.call(m.sourceHash);
    if (src == null && requestPath != null) {
      // We received a message but never heard the sender's announce (common on
      // busy/asymmetric public hubs). Pull the source's path so we can resolve
      // its identity and verify the signature, then retry briefly.
      log?.call('lxmf: unknown source — requesting its path to verify');
      requestPath!(m.sourceHash);
      final deadline = DateTime.now().add(const Duration(seconds: 12));
      while (src == null && DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 300));
        src = identityForDest?.call(m.sourceHash);
      }
    }
    if (src == null) {
      // Source unresolvable. If the payload self-authenticates at the app layer
      // (e.g. a signed wapp datagram), deliver it anyway — LXMF-layer verification
      // is redundant there and would otherwise drop valid traffic on quiet hubs.
      if (acceptUnverified?.call(m) ?? false) {
        log?.call('lxmf: unknown source but self-authenticating payload — delivering');
        onMessage?.call(m);
        return;
      }
      log?.call('lxmf: message from unknown source (no announce) — dropped');
      return;
    }
    if (!await m.verify(src)) {
      log?.call('lxmf: signature verification FAILED — dropped');
      return;
    }
    log?.call('lxmf: message ${_hex(m.hash).substring(0, 8)} verified, delivering');
    onMessage?.call(m);
  }

  void _sendBody(_LxOut e) {
    if (e.packed.length <= _linkPacketMax) {
      send(e.link.encrypt(e.packed, context: RnsContext.none).pack());
      if (!e.done.isCompleted) e.done.complete(true); // packet delivery
    } else {
      try {
        final s = RnsResourceSender(e.link, e.packed)..prepare();
        e.sender = s;
        send(s.advertisementPacket().pack());
      } catch (err) {
        log?.call('lxmf: resource prepare failed: $err');
        if (!e.done.isCompleted) e.done.complete(false);
      }
    }
  }

  // ── Outbound (initiator) ───────────────────────────────────────────────────
  Future<void> _onOut(_LxOut e, RnsPacket p) async {
    if (!e.sent) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(false);
          return;
        }
        send(rtt.pack());
        e.sent = true;
        // Give the peer a moment to activate the link and install its delivery
        // callbacks before sending the message — otherwise a fast responder (a
        // real LXMF/RNS node) may receive the message packet before the link is
        // fully established and drop it.
        Future.delayed(const Duration(milliseconds: 500), () => _sendBody(e));
      }
      return;
    }
    // Resource delivery in progress.
    switch (p.context) {
      case RnsContext.resourceReq:
        final s = e.sender;
        if (s != null) {
          for (final part in s.handleRequest(e.link.decrypt(p))) {
            send(part.pack());
          }
        }
        break;
      case RnsContext.resourcePrf:
        final s = e.sender;
        // RNS resource proofs are UNENCRYPTED — validate raw p.data.
        if (s != null && s.validateProof(p.data) && !s.complete) {
          send(s.advertisementPacket().pack()); // next segment
          break;
        }
        if (!e.done.isCompleted) e.done.complete(true);
        break;
      default:
        break;
    }
  }

  // ── Propagation responder (serve a peer pulling its mailbox) ─────────────
  Future<void> _acceptProp(RnsPacket request) async {
    try {
      final link = await RnsLink.responder(identity, request);
      _propIn[_hex(link.linkId!)] = _PropIn(link);
      send((await link.buildProof()).pack());
    } catch (e) {
      log?.call('lxmf: accept propagation link failed: $e');
    }
  }

  Future<void> _onPropIn(_PropIn e, RnsPacket p) async {
    if (e.link.status != RnsLinkStatus.active && p.context == RnsContext.lrrtt) {
      e.link.handleRtt(p);
      return;
    }
    if (p.context == _ctxSyncReq) {
      // data = the requester's delivery-dest hash. Serve each held message as its
      // OWN single link packet (robust over a flaky/asymmetric link: each is an
      // independent small transfer, a lost one is just re-sent on the next pull —
      // the receiver dedups by message hash). Oversized messages (e.g. keysets)
      // that don't fit one packet fall back to a single batched Resource.
      final who = _hex(e.link.decrypt(p));
      final held = _mailbox[who] ?? const [];
      log?.call('lxmf: propagation pull from ${who.substring(0, 8)} '
          '(${held.length} held)');
      e.servedFor = who;
      if (held.isEmpty) {
        send(e.link.encrypt(Uint8List(0), context: _ctxSyncEnd).pack());
        return;
      }
      final big = held.where((m) => m.length > _linkPacketMax).toList();
      if (big.isEmpty) {
        // Common case (chat history): one small packet per message + an end mark.
        // The mailbox is dropped only when the initiator ACKs (see _ctxSyncAck).
        for (final m in held) {
          send(e.link.encrypt(m, context: _ctxSyncMsg).pack());
        }
        send(e.link.encrypt(Uint8List(0), context: _ctxSyncEnd).pack());
        return;
      }
      // Fallback for batches containing oversized messages: one Resource.
      final s = RnsResourceSender(e.link, _packBatch(held))..prepare();
      e.sender = s;
      send(s.advertisementPacket().pack());
      return;
    }
    if (p.context == _ctxSyncAck) {
      if (e.servedFor != null) { _mailbox.remove(e.servedFor); _mailboxKeys.remove(e.servedFor); } // delivered → drop
      return;
    }
    if (p.context == RnsContext.resourceReq && e.sender != null) {
      for (final part in e.sender!.handleRequest(e.link.decrypt(p))) {
        send(part.pack());
      }
      return;
    }
    if (p.context == RnsContext.resourcePrf && e.sender != null) {
      final s = e.sender!;
      // RNS resource proofs are UNENCRYPTED — validate raw p.data.
      if (s.validateProof(p.data) && !s.complete) {
        send(s.advertisementPacket().pack()); // next segment
        return;
      }
      if (e.servedFor != null) { _mailbox.remove(e.servedFor); _mailboxKeys.remove(e.servedFor); } // delivered → drop
      return;
    }
  }

  // ── Propagation initiator (pull our messages from a peer mailbox) ─────────
  /// Open a link to [propDestHash] (a peer's propagation destination) and pull
  /// any messages it is holding for us, delivering+verifying each. Returns the
  /// number delivered. Auto-requests a path to the peer if we have none.
  Future<int> pullFrom(Uint8List propDestHash,
      {Duration timeout = const Duration(seconds: 30)}) async {
    var rid = identityForDest?.call(propDestHash);
    if (rid == null && requestPath != null) {
      requestPath!(propDestHash);
      final deadline = DateTime.now().add(const Duration(seconds: 12));
      while (rid == null && DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 300));
        rid = identityForDest?.call(propDestHash);
      }
    }
    if (rid == null) {
      log?.call('lxmf: no path to propagation node — cannot pull');
      return 0;
    }
    final link =
        await RnsLink.initiator(rid, kLxmfApp, kLxmfPropagationAspects);
    link.nextHop = nextHopFor?.call(rid);
    final reqPkt = link.buildRequest(); // sets linkId
    final entry = _PropOut(link, Completer<int>());
    final id = _hex(link.linkId!);
    _propOut[id] = entry;
    send(reqPkt.pack());
    final n = await entry.done.future.timeout(timeout, onTimeout: () => entry.count);
    _propOut.remove(id);
    return n;
  }

  Future<void> _onPropOut(_PropOut e, RnsPacket p) async {
    if (!e.active) {
      if (p.packetType == RnsPacketType.proof &&
          p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(e.count);
          return;
        }
        send(rtt.pack());
        e.active = true;
        // Ask for messages addressed to OUR delivery destination.
        Future.delayed(const Duration(milliseconds: 300), () {
          send(e.link.encrypt(deliveryDestHash, context: _ctxSyncReq).pack());
        });
      }
      return;
    }
    switch (p.context) {
      case _ctxSyncMsg: // one held message as a single packet
        e.count++;
        await _deliver(e.link.decrypt(p));
        break;
      case RnsContext.resourceAdv:
      case RnsContext.resourceHmu:
      case RnsContext.resource:
        final rx = e.rx ??= RnsResourceReceiver(e.link);
        for (final pkt in rx.handle(p)) {
          send(pkt.pack());
        }
        if (rx.complete) {
          for (final m in _unpackBatch(rx.payload!)) {
            e.count++;
            await _deliver(m);
          }
          // ACK so the responder can drop its mailbox for us.
          send(e.link.encrypt(Uint8List(0), context: _ctxSyncAck).pack());
          if (!e.done.isCompleted) e.done.complete(e.count);
          e.rx = null;
        } else if (rx.error != null) {
          e.rx = null;
        }
        break;
      case _ctxSyncEnd: // end of the per-message batch (or empty mailbox)
        // ACK so the responder drops the mailbox; the receiver dedups, and the
        // wapp's history retry re-pulls anything a lost packet missed.
        send(e.link.encrypt(Uint8List(0), context: _ctxSyncAck).pack());
        if (!e.done.isCompleted) e.done.complete(e.count);
        break;
      default:
        break;
    }
  }

  // Length-prefixed batch of held messages: u32 count, then [u32 len, bytes]*.
  static Uint8List _packBatch(List<Uint8List> msgs) {
    final b = BytesBuilder();
    _putU32(b, msgs.length);
    for (final m in msgs) {
      _putU32(b, m.length);
      b.add(m);
    }
    return b.toBytes();
  }

  static List<Uint8List> _unpackBatch(Uint8List blob) {
    final out = <Uint8List>[];
    if (blob.length < 4) return out;
    var o = 0;
    final n = _getU32(blob, o);
    o += 4;
    for (var k = 0; k < n && o + 4 <= blob.length; k++) {
      final len = _getU32(blob, o);
      o += 4;
      if (o + len > blob.length) break;
      out.add(Uint8List.sublistView(blob, o, o + len));
      o += len;
    }
    return out;
  }

  static void _putU32(BytesBuilder b, int v) =>
      b.add([(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
  static int _getU32(Uint8List d, int o) =>
      (d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

class _PropIn {
  final RnsLink link;
  RnsResourceSender? sender; // serving a held-message batch as a resource
  String? servedFor; // recipient hex whose mailbox we're serving
  _PropIn(this.link);
}

class _PropOut {
  final RnsLink link;
  final Completer<int> done;
  bool active = false;
  int count = 0;
  RnsResourceReceiver? rx; // receiving the held-message batch
  _PropOut(this.link, this.done);
}
