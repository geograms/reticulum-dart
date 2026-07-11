/*
 * RelayNode — a NOSTR relay/indexer endpoint on the Dart Reticulum stack.
 *
 * Registers a 'geogram'/['relay'] destination and answers relay requests over an
 * RnsLink (responder side): EVENT publishes an event into the local
 * [RelayEventStore], REQ runs a NIP-01 filter (incl. NIP-50 search) and returns
 * the matches, COUNT returns a tally. As a client (initiator side) it can
 * publish/query/count against another relay's identity.
 *
 * Transport-agnostic like FileTransferNode / LxmfRouter: the owner supplies
 * [send] (e.g. transport.sendOnAll) and [nextHopFor] (transport addressing for
 * routed peers). Request and response each ride the link as a single encrypted
 * packet when small, else as an RNS Resource — the shared [_RelayLink] session
 * demuxes both directions by packet context (only one transfer is in flight at a
 * time in a request/response exchange, so contexts never collide).
 */
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../reticulum/rns_crypto.dart';
import '../reticulum/rns_identity.dart';
import '../reticulum/rns_link.dart';
import '../reticulum/rns_packet.dart';
import '../reticulum/rns_resource.dart';
import '../reticulum/rns_resource_receiver.dart';
import '../reticulum/lxmf/lxmf.dart';
import '../reticulum/lxmf/lxmf_message.dart';
import '../reticulum/lxmf/lxmf_router.dart';
import '../../util/nostr_event.dart';
import '../../util/nostr_crypto.dart';
import 'relay_event_store.dart';
import 'relay_protocol.dart';
import '../../util/npd.dart';
import 'spam.dart';

const String kRelayApp = 'geogram';
const List<String> kRelayAspects = ['relay'];

// Max relay message we send as a single link packet (else an RNS Resource).
const int _pktMax = 360;

class RelayNode {
  final RnsIdentity identity;
  final RelayEventStore store;
  final void Function(Uint8List raw) send;
  final Uint8List? Function(RnsIdentity peer)? nextHopFor;
  /// Per-destination next-hop + path-exists (Reticulum routes per-destination;
  /// see RnsLink.ensurePath). Prefer these over [nextHopFor].
  final Uint8List? Function(Uint8List destHash)? nextHopForDest;
  final bool Function(Uint8List destHash)? hasPathForDest;
  /// Pull a transport path to a peer we know by identity but have no cached route
  /// to (its announce was never flooded to us on busy hubs), so a relay query
  /// link is routable. See FileTransferNode.requestPath.
  final void Function(Uint8List destHash)? requestPath;
  final void Function(String msg)? log;

  /// Optional anti-spam acceptance policy applied to inbound EVENTs (PoW / rate
  /// / size). Null = accept anything with a valid signature.
  final SpamPolicy? spam;

  /// Whether to act as a relay SERVER (accept inbound links and answer
  /// EVENT/REQ/COUNT from the network). A phone/leaf sets this false: it still
  /// queries other relays (the client API below), but never serves the network
  /// — serving the whole network's queries off the device store pegged the UI
  /// isolate (57 MB/s of sqlite reads) and ANR'd the app. Mutable so the owner
  /// can flip hosting on/off at runtime (capacity / settings switch).
  bool serve;

  /// Hosting tier classifier: maps an author pubkey (hex) to a retention tier
  /// index (0 self / 1 followed / 2 stranger). Null = treat everyone as stranger.
  int Function(String pubHex)? tierOfPub;

  /// Hosting admission gate for inbound EVENTs: returns a rejection reason, or
  /// null to accept. Null hook = accept (subject only to spam). Lets the owner
  /// enforce per-tier quotas without coupling the relay to the policy.
  String? Function(NostrEvent ev, int tier)? admitEvent;

  /// Called whenever an event is accepted via an inbound EVENT (so the owner can
  /// fan it out / re-index). Optional.
  void Function(NostrEvent event)? onEvent;

  late final Uint8List relayDestHash =
      RnsDestination.hash(identity, kRelayApp, kRelayAspects);

  final Map<String, _RelayLink> _in = {}; // responder links by link-id hex
  final Map<String, _Pending> _out = {}; // initiator requests by link-id hex
  int _subSeq = 0;

  /// Our own NOSTR pubkey (hex). When [serve] is false (a phone/leaf that won't
  /// host the whole network) the node still answers queries for ITS OWN posts —
  /// this returns that pubkey so the responder can scope a leaf's REQ to
  /// self-authored events. Null disables even self-serving.
  String? Function()? selfPubHex;

  RelayNode({
    required this.identity,
    required this.store,
    required this.send,
    this.nextHopFor,
    this.nextHopForDest,
    this.hasPathForDest,
    this.requestPath,
    this.spam,
    this.onEvent,
    this.log,
    this.serve = true,
    this.tierOfPub,
    this.admitEvent,
    this.selfPubHex,
  });

  /// Feed an inbound packet; true if it belonged to the relay.
  /// True when this node will answer at least its OWN posts to a querier — i.e.
  /// it serves the whole network ([serve]) OR it can scope to self-authored
  /// events (a leaf with a known self pubkey). Lets a phone share what it
  /// posted without hosting the network ("ask the poster for its posts").
  bool get _answersQueries => serve || (selfPubHex?.call() != null);

  Future<bool> handlePacket(RnsPacket p) async {
    // Order matters: the cheap packet-type + dest-hash checks gate the call to
    // [_answersQueries], which may do real work (resolving our pubkey). Putting
    // them first keeps this O(1) for the flood of unrelated packets on a busy
    // hub — evaluating _answersQueries per packet pegged the CPU and hung the
    // app.
    if (p.packetType == RnsPacketType.linkRequest &&
        RnsCrypto.constantTimeEquals(p.destHash, relayDestHash) &&
        _answersQueries) {
      await _accept(p);
      return true;
    }
    if (p.destType == RnsDestType.link) {
      final id = _hex(p.destHash);
      final i = _in[id];
      if (i != null) {
        if (i.link.status != RnsLinkStatus.active &&
            p.context == RnsContext.lrrtt) {
          i.link.handleRtt(p);
        } else {
          i.handleData(p);
        }
        return true;
      }
      final o = _out[id];
      if (o != null) {
        await _onOut(o, p);
        return true;
      }
    }
    return false;
  }

  // ── Client API ──────────────────────────────────────────────────────────

  /// Publish [e] to the relay owned by [relay]. Returns true if it was stored.
  Future<bool> publish(RnsIdentity relay, NostrEvent e,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final r = await _request(relay, RelayProtocol.event(e), timeout: timeout);
    return r != null && r.op == RelayOp.stored && r.ok;
  }

  /// Run a NIP-01 filter (set [NostrFilter.search] for NIP-50) against [relay].
  Future<List<NostrEvent>> query(RnsIdentity relay, NostrFilter filter,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final sub = 's${_subSeq++}';
    final r = await _request(relay, RelayProtocol.req(sub, filter),
        timeout: timeout);
    return r?.events ?? const [];
  }

  /// Count matches for [filter] on [relay].
  Future<int> countMatches(RnsIdentity relay, NostrFilter filter,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final sub = 's${_subSeq++}';
    final r = await _request(relay, RelayProtocol.count(sub, filter),
        timeout: timeout);
    return r?.count ?? 0;
  }

  /// Store-and-forward: deposit a packed LXMF message at propagation node
  /// [propNode] for offline recipient [recipientDeliveryDestHex]. Returns true
  /// if the node accepted it into its mailbox.
  Future<bool> deposit(
      RnsIdentity propNode, String recipientDeliveryDestHex, Uint8List packed,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final r = await _request(
        propNode, RelayProtocol.deposit(recipientDeliveryDestHex, packed),
        timeout: timeout);
    return r != null && r.op == RelayOp.stored && r.ok;
  }

  /// Recipient-authorized delete: ask [relay] to drop [ids]. [reqPubHex] is our
  /// NOSTR pubkey and [sigHex] a BIP-340 signature by it over
  /// sha256(ids.join(',')). The relay drops only ids whose event has a `p` tag
  /// == reqPubHex (i.e. addressed to us). Returns the number it dropped.
  Future<int> dropForRecipient(
      RnsIdentity relay, List<String> ids, String reqPubHex, String sigHex,
      {Duration timeout = const Duration(seconds: 20)}) async {
    if (ids.isEmpty) return 0;
    final r = await _request(relay, RelayProtocol.drop(reqPubHex, ids, sigHex),
        timeout: timeout);
    return (r != null && r.op == RelayOp.dropRes) ? r.count : 0;
  }

  /// Indexer side: deliver any mail queued for [recipient] (now believed online)
  /// via [router]. Removes each message once delivered. Returns delivered count.
  Future<int> flushFor(RnsIdentity recipient, LxmfRouter router) async {
    final destHex =
        _hex(RnsDestination.hash(recipient, kLxmfApp, kLxmfDeliveryAspects));
    var delivered = 0;
    for (final item in store.sfPending(destHex)) {
      final msg = LxmfMessage.unpack(item.blob);
      if (msg == null) {
        store.sfDelete(item.msgId); // undecodable — drop
        continue;
      }
      if (await router.send_(msg)) {
        store.sfDelete(item.msgId);
        delivered++;
      }
    }
    return delivered;
  }

  /// Does the mailbox hold anything for this recipient's delivery dest?
  bool hasMailFor(RnsIdentity recipient) {
    final destHex =
        _hex(RnsDestination.hash(recipient, kLxmfApp, kLxmfDeliveryAspects));
    return store.sfCount(destHex) > 0;
  }

  /// Next hop to [relay]'s relay destination, pulling a path first if we have
  /// none (we may know the peer's identity without a cached route). Mirrors
  /// FileTransferNode._ensurePath / LxmfRouter.
  Future<Uint8List?> _ensurePath(RnsIdentity relay) =>
      RnsLink.ensurePath(relay, kRelayApp, kRelayAspects,
          nextHopFor: nextHopFor,
          nextHopForDest: nextHopForDest,
          hasPathForDest: hasPathForDest,
          requestPath: requestPath);

  Future<RelayFrame?> _request(RnsIdentity relay, Uint8List reqBytes,
      {required Duration timeout}) async {
    final link = await RnsLink.initiator(relay, kRelayApp, kRelayAspects);
    link.nextHop = await _ensurePath(relay);
    final reqPkt = link.buildRequest();
    final done = Completer<RelayFrame?>();
    final rl = _RelayLink(link, send, (msg) {
      if (!done.isCompleted) done.complete(RelayProtocol.decode(msg));
    });
    final pending = _Pending(link, rl, reqBytes, done);
    final id = _hex(link.linkId!);
    _out[id] = pending;
    send(reqPkt.pack());
    final r = await done.future.timeout(timeout, onTimeout: () => null);
    _out.remove(id);
    return r;
  }

  Future<void> _onOut(_Pending e, RnsPacket p) async {
    if (e.link.status != RnsLinkStatus.active) {
      if (p.packetType == RnsPacketType.proof &&
          p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(null);
          return;
        }
        send(rtt.pack());
        e.rl.sendMessage(e.requestBytes); // link is active now
      }
      return;
    }
    e.rl.handleData(p);
  }

  // ── Connectionless probe (NPD) ────────────────────────────────────────────

  /// Answer a connectionless probe carrying a REQ, WITHOUT a link.
  ///
  /// Returns null when we hold nothing — the caller then sends no packet at all,
  /// which is the entire point: that case was 98 of 98 inbound queries and each
  /// one was buying a full Curve25519 handshake to say "I have nothing".
  ///
  /// Query semantics are identical to the link path ([_serve], RelayOp.req),
  /// self-scoping included, so a probe and a link answer the same question the
  /// same way.
  Future<({int type, Uint8List body})?> answerProbe(Uint8List body) async {
    final f = RelayProtocol.decode(body);
    if (f == null || f.op != RelayOp.req || f.filter == null) return null;
    if (!_answersQueries) return null;

    var filter = f.filter!;
    if (!serve) {
      final self = selfPubHex?.call();
      if (self == null) return null; // nothing of ours to offer -> silence
      filter = NostrFilter(
        authors: [self.toLowerCase()],
        kinds: filter.kinds,
        tags: filter.tags,
        since: filter.since,
        until: filter.until,
        limit: filter.limit,
      );
    }

    final events = store.query(filter);
    if (events.isEmpty) return null; // <- silence. no reply, no crypto.

    // We have something. Send it inline if it fits one datagram; otherwise just
    // say HOW MANY and let the peer open a link for the bulk (the link is worth
    // paying for when there is actually data to move).
    final full = RelayProtocol.result(f.subId ?? '', events, true);
    if (full.length <= kNpdMaxPlaintext) {
      log?.call('relay: probe answered inline -> ${events.length} event(s)');
      return (type: NpdType.result, body: full);
    }
    log?.call('relay: probe -> HAVE ${events.length} (open a link)');
    return (
      type: NpdType.have,
      body: RelayProtocol.countResult(f.subId ?? '', events.length),
    );
  }

  // ── Responder side ────────────────────────────────────────────────────────

  Future<void> _accept(RnsPacket request) async {
    // Dedup BEFORE the crypto. The link-id is a cheap truncated hash of the
    // request, while RnsLink.responder costs two Curve25519 scalar mults and
    // buildProof costs an Ed25519 signature. The SAME LINKREQUEST reaches us
    // once per interface it arrives on (and this runs ahead of the transport's
    // packet dedup), so without this check one peer's single request bought N
    // full handshakes. Re-send the CACHED proof bytes instead — re-calling
    // buildProof would sign again, which is the very cost we are avoiding.
    final id = _hex(RnsLink.linkIdFromRequest(request));
    final known = _in[id];
    if (known != null) {
      final proof = known.proof;
      if (proof != null) send(proof);
      return;
    }
    try {
      final link = await RnsLink.responder(identity, request);
      final rl = _RelayLink(link, send, (msg) => _serve(link, msg));
      _in[id] = rl;
      final proof = (await link.buildProof()).pack();
      rl.proof = proof;
      send(proof);
    } catch (err) {
      log?.call('relay: accept link failed: $err');
    }
  }

  void _serve(RnsLink link, Uint8List msg) {
    final f = RelayProtocol.decode(msg);
    final rl = _in[_hex(link.linkId!)];
    if (f == null || rl == null) return;
    try {
      switch (f.op) {
        case RelayOp.event:
          // A leaf (serve=false) accepts query links so it can share its own
          // posts, but it does NOT store other people's events pushed at it.
          if (!serve) {
            rl.sendMessage(RelayProtocol.stored(false, 'not a host'));
            break;
          }
          final ev = f.event;
          if (ev == null) {
            rl.sendMessage(RelayProtocol.stored(false, 'no event'));
            break;
          }
          final verdict = spam?.check(ev);
          if (verdict != null && !verdict.accepted) {
            rl.sendMessage(RelayProtocol.stored(false, verdict.reason));
            break;
          }
          // Hosting tier + quota: classify the author, then run the admission
          // gate. self (0) is always admitted; strangers can be refused past
          // their monthly note / storage caps.
          final tier = tierOfPub?.call(ev.pubkey) ?? 2;
          final reject = admitEvent?.call(ev, tier);
          if (reject != null) {
            rl.sendMessage(RelayProtocol.stored(false, reject));
            break;
          }
          final ok = store.put(ev, tier: tier);
          if (ok) onEvent?.call(ev);
          rl.sendMessage(RelayProtocol.stored(ok, ok ? null : 'rejected'));
          break;
        case RelayOp.req:
          // Full hosts answer the whole query; a leaf scopes it to its OWN
          // posts (cheap + safe) so a joiner can still pull what this device
          // published, decentralised, without anyone hosting the network.
          var filter = f.filter!;
          if (!serve) {
            final self = selfPubHex?.call();
            if (self == null) {
              rl.sendMessage(RelayProtocol.result(f.subId ?? '', const [], true));
              break;
            }
            // Scope to our own posts: keep the querier's kinds/tags/since/limit
            // but force authors to just us.
            filter = NostrFilter(
              authors: [self.toLowerCase()],
              kinds: filter.kinds,
              tags: filter.tags,
              since: filter.since,
              until: filter.until,
              limit: filter.limit,
            );
          }
          final events = store.query(filter);
          log?.call('relay: answered REQ -> ${events.length} event(s)'
              '${serve ? '' : ' (self-scoped)'}');
          rl.sendMessage(RelayProtocol.result(f.subId ?? '', events, true));
          break;
        case RelayOp.count:
          final n = store.count(f.filter);
          rl.sendMessage(RelayProtocol.countResult(f.subId ?? '', n));
          break;
        case RelayOp.deposit:
          final dest = f.dest;
          final blob = f.blob;
          var ok = false;
          if (dest != null && blob != null && blob.isNotEmpty) {
            final msgId = _hex(crypto.sha256.convert(blob).bytes);
            ok = store.sfDeposit(msgId: msgId, dest: dest, blob: blob);
            // ok==false also means "already queued" — treat as accepted.
            ok = true;
          }
          rl.sendMessage(RelayProtocol.stored(ok, ok ? null : 'rejected'));
          break;
        case RelayOp.drop:
          // Recipient-authorized delete: verify the requester owns reqPub (a
          // BIP-340 sig over sha256 of the comma-joined ids), then drop only the
          // ids whose event is p-tagged to reqPub. Never deletes a third party's
          // events, and an unauthenticated request drops nothing.
          final reqPub = f.reqPub;
          final ids = f.ids;
          final sig = f.sig;
          var dropped = 0;
          if (serve && reqPub != null && ids != null && sig != null &&
              ids.isNotEmpty) {
            final digest =
                crypto.sha256.convert(utf8.encode(ids.join(','))).bytes;
            final msgHex = _hex(Uint8List.fromList(digest));
            var okSig = false;
            try {
              okSig = NostrCrypto.schnorrVerify(msgHex, sig, reqPub);
            } catch (_) {
              okSig = false;
            }
            if (okSig) dropped = store.dropForRecipient(ids, reqPub);
          }
          rl.sendMessage(RelayProtocol.dropResult(dropped));
          break;
        default:
          break;
      }
    } catch (err) {
      log?.call('relay: serve error: $err');
    }
  }

  /// Drop idle responder links (call periodically from the owner).
  void pruneLinks() => _in.clear();

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

class _Pending {
  final RnsLink link;
  final _RelayLink rl;
  final Uint8List requestBytes;
  final Completer<RelayFrame?> done;
  _Pending(this.link, this.rl, this.requestBytes, this.done);
}

/// One full-duplex message channel over an established link. Sends one message
/// at a time (packet or Resource) and assembles one inbound message at a time;
/// in a request/response exchange the two never overlap, so inbound packets are
/// demuxed purely by context.
class _RelayLink {
  final RnsLink link;
  final void Function(Uint8List raw) send;
  final void Function(Uint8List msg) onMessage;

  RnsResourceSender? _tx; // our outbound Resource (if the message is large)
  RnsResourceReceiver? _rx; // inbound Resource being assembled

  /// The packed LRPROOF we already sent. Cached so a duplicate LINKREQUEST
  /// (same request arriving on another interface) is answered without signing
  /// it again.
  Uint8List? proof;

  _RelayLink(this.link, this.send, this.onMessage);

  /// Send [msg] over the link — single packet if it fits, else a Resource.
  void sendMessage(Uint8List msg) {
    if (msg.length <= _pktMax) {
      send(link.encrypt(msg, context: RnsContext.none).pack());
      return;
    }
    final s = RnsResourceSender(link, msg)..prepare();
    _tx = s;
    send(s.advertisementPacket().pack());
  }

  void handleData(RnsPacket p) {
    switch (p.context) {
      case RnsContext.resourceReq: // peer requests parts of our outbound Resource
        final tx = _tx;
        if (tx != null) {
          for (final part in tx.handleRequest(link.decrypt(p))) {
            send(part.pack());
          }
        }
        break;
      case RnsContext.resourcePrf: // peer proved receipt of a segment
        final tx = _tx;
        // RNS resource proofs are UNENCRYPTED — validate raw p.data.
        if (tx != null && tx.validateProof(p.data)) {
          if (!tx.complete) {
            send(tx.advertisementPacket().pack()); // next segment
          } else {
            _tx = null;
          }
        }
        break;
      case RnsContext.none: // a complete single-packet message
        onMessage(link.decrypt(p));
        break;
      case RnsContext.resourceAdv: // start/continue receiving an inbound Resource
      case RnsContext.resourceHmu:
      case RnsContext.resource:
        final rx = _rx ??= RnsResourceReceiver(link);
        for (final pkt in rx.handle(p)) {
          send(pkt.pack());
        }
        if (rx.complete) {
          _rx = null;
          onMessage(rx.payload!);
        } else if (rx.error != null) {
          _rx = null;
        }
        break;
      default:
        break;
    }
  }
}
