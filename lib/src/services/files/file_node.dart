/*
 * FileTransferNode — wires the file-transfer sessions to a live Reticulum
 * transport. It is the per-node hub that:
 *   - serves files: accepts inbound LINKREQUESTs to our "files" destination,
 *     completes the link handshake (responder), and runs a FileServeSession that
 *     answers GET_MANIFEST/GET_CHUNK from a FileSource;
 *   - fetches files: opens a link to a provider's "files" destination (initiator),
 *     then runs a FileFetchSession to pull + verify a file by its sha256.
 *
 * Transport-agnostic: the owner supplies a [send] callback (e.g.
 * transport.sendOnAll) and feeds inbound packets to [handlePacket]. Link/file
 * packets are addressed by link_id, so broadcasting replies on all interfaces is
 * correct (the wrong peer ignores them); transport-routed unicast is a later
 * optimization.
 */
import 'dart:async';
import 'dart:typed_data';

import '../reticulum/rns_crypto.dart';
import '../reticulum/rns_identity.dart';
import '../reticulum/rns_link.dart';
import '../reticulum/rns_packet.dart';
import 'dht/dht_core.dart';
import 'dht/dht_message.dart';
import 'dht/dht_node.dart';
import 'dht/provider_record.dart';
import 'file_transfer.dart';
import 'serve_quota.dart';

const String kFilesApp = 'geogram';
const List<String> kFilesAspects = ['files'];

class _ServeEntry {
  final RnsLink link;
  final FileServeSession serve;
  _ServeEntry(this.link, this.serve);
}

class _FetchEntry {
  final RnsLink link;
  final Uint8List fileHash;
  final Completer<Uint8List?> done;
  FileFetchSession? fetch; // null until the link is active
  Timer? timeout;
  Timer? retry; // periodic stall-recovery (re-request missing parts)
  Duration baseTimeout = const Duration(minutes: 20);
  _FetchEntry(this.link, this.fileHash, this.done);
}

class _DhtRpcEntry {
  final RnsLink link;
  final Uint8List reqBytes;
  final Completer<Uint8List?> done = Completer<Uint8List?>();
  bool sent = false; // request sent (link active)
  _DhtRpcEntry(this.link, this.reqBytes);
}

class _DepositEntry {
  final RnsLink link;
  final Uint8List sha;
  final Uint8List bytes;
  final String ext;
  final Uint8List pub;
  final Uint8List sig;
  final Completer<bool> done;
  FileDepositSession? dep; // null until the link is active
  Timer? timeout;
  _DepositEntry(
      this.link, this.sha, this.bytes, this.ext, this.pub, this.sig, this.done);
}

class _Provided {
  final Uint8List sha;
  final int capacity;
  final Uint8List? manifestHash;
  _Provided(this.sha, this.capacity, this.manifestHash);
}

class FileTransferNode {
  final RnsIdentity identity; // our identity (must hold private keys)
  final FileSource source; // what we serve
  final void Function(Uint8List raw) send; // e.g. transport.sendOnAll
  final void Function(String msg)? log;

  late final Uint8List filesDestHash =
      RnsDestination.hash(identity, kFilesApp, kFilesAspects);
  late final Uint8List dhtDestHash =
      RnsDestination.hash(identity, kDhtApp, kDhtAspects);

  final Map<String, _ServeEntry> _serve = {}; // link_id hex -> serve
  final Map<String, _FetchEntry> _fetch = {}; // link_id hex -> fetch
  // DHT links: responder links we host, and in-flight outbound RPC links.
  final Map<String, RnsLink> _dhtServeLinks = {};
  final List<String> _dhtServeOrder = [];
  final Map<String, _DhtRpcEntry> _dhtRpcByLink = {};
  static const int _maxDhtServeLinks = 128;
  // Live download progress for the UI: file sha hex -> (received, total) bytes,
  // updated as a fetch advances and cleared when it ends (total 0 = indeterminate).
  final Map<String, ({int received, int total})> _fetchProgress = {};
  // Files we advertise, for periodic republish (TTL refresh).
  final Map<String, _Provided> _provided = {};
  // Arbitrary DHT keys we advertise regardless of the file serve-quota (used for
  // folder discovery: folderId -> provider). Republished alongside files.
  final Map<String, _Provided> _providedKeys = {};

  /// The Kademlia index node (provider lookup/publish). Null unless [enableDht].
  DhtNode? dht;

  /// Serving-side budget / anti-abuse guard applied to everything we serve.
  final ServeQuota serveQuota;

  /// Legacy per-identity next-hop resolver (any of the identity's paths). Reticulum
  /// routes per-DESTINATION, so prefer [nextHopForDest]/[hasPathForDest] below;
  /// this stays only as a fallback.
  final Uint8List? Function(RnsIdentity peer)? nextHopFor;

  /// Per-destination next-hop transport (null = direct neighbour). Supplied by the
  /// host (RnsTransport.pathFor(destHash).nextHop). Routing is per-destination —
  /// the same node's files/dht/chat dests can be reached via different hubs — so
  /// the link request MUST be transport-addressed to the hub that has a route to
  /// THIS specific destination, or the intermediate hub drops it.
  final Uint8List? Function(Uint8List destHash)? nextHopForDest;

  /// Whether the host has a path to [destHash] (RnsTransport.hasPath).
  final bool Function(Uint8List destHash)? hasPathForDest;

  /// Hardware MTU of the interface a packet to [destHash] would leave on
  /// (RnsTransport.nextHopInterfaceHwMtu). Lets an outbound link offer a larger
  /// link MTU over TCP (link MTU discovery). Null → no discovery (500).
  final int Function(Uint8List destHash)? nextHopMtuForDest;

  /// Pull a transport path to [destHash] (a PATH_REQUEST). Supplied by the host
  /// (RnsTransport.requestPath). Needed because we often know a peer's IDENTITY
  /// (e.g. a DHT contact learned from an incoming STORE) without having a cached
  /// path to it — its announce was never passively flooded to us on busy/
  /// asymmetric public hubs. A path request is a PULL the peer's attached hub
  /// answers on our direct link, so the DHT/file links below become routable.
  final void Function(Uint8List destHash)? requestPath;

  /// Called when we serve a file's manifest to another node (one download by a
  /// peer), with the 32-byte file hash. Drives the per-file download metric.
  final void Function(Uint8List fileHash)? onServed;

  /// Store-and-forward hosting hooks (see FileServeSession). When both are set
  /// this node accepts blob deposits from peers; null = deposits declined.
  final DepositVerdict Function(
      Uint8List sha, int size, String ext, String pubHex, String sigHex)?
      onDepositOffer;
  final void Function(
      Uint8List sha, Uint8List bytes, String originPubHex, int tier, String ext)?
      onDepositStore;

  FileTransferNode({
    required this.identity,
    required this.source,
    required this.send,
    this.log,
    bool enableDht = false,
    ServeQuota? serveQuota,
    this.nextHopFor,
    this.nextHopForDest,
    this.hasPathForDest,
    this.requestPath,
    this.nextHopMtuForDest,
    this.onServed,
    this.onDepositOffer,
    this.onDepositStore,
  }) : serveQuota = serveQuota ?? ServeQuota() {
    if (enableDht) {
      // k=24 (vs the Kademlia default 8): a geogram overlay is small (tens of
      // nodes), so a wider fanout makes resolve()/publish() query/replicate to
      // (nearly) ALL peers — crucially including the actual holder, which keeps
      // its own record locally. With k=8 a resolver only asked the 8 closest to
      // the key, which can exclude the holder once the overlay grows past 8, so a
      // freshly-published file resolved 0 providers even though its holder was
      // meshed. k=24 closes that gap on the small networks we actually run.
      dht = DhtNode(identity: identity, k: 24, sendRpc: _dhtSendRpc, log: log);
    }
  }

  /// Resolve the next hop to [peer]'s (app, aspects) destination, pulling a path
  /// first if we don't have one. We may know the peer's identity (a DHT contact)
  /// without a cached path because its announce was never flooded to us on busy
  /// hubs; a PATH_REQUEST is answered by the hub the peer is attached to. Mirrors
  /// LxmfRouter's request-then-wait. Returns the hop (may still be null).
  Future<Uint8List?> _ensurePath(
          RnsIdentity peer, String app, List<String> aspects) =>
      RnsLink.ensurePath(peer, app, aspects,
          nextHopFor: nextHopFor,
          nextHopForDest: nextHopForDest,
          hasPathForDest: hasPathForDest,
          requestPath: requestPath,
          // A path PULL to a provider we resolved via the DHT (whose announce we
          // never heard) must cross to the hub it's attached to and back. 3s is
          // too short on busy/asymmetric public hubs and makes the file link open
          // unroutable (broadcast) → handshake timeout. Give it ~9s before
          // falling back, well within the 12s provider-ready window.
          maxPolls: 30);

  /// Learn a peer (from its announce) as a DHT contact.
  void addPeerFromAnnounce(RnsIdentity peer) =>
      dht?.routing.add(DhtContact.ofIdentity(peer));

  /// Warm-start the DHT overlay from a cache of known peer public keys (64-byte
  /// RNS public keys, e.g. from a persisted observed-node store). Seeds the
  /// routing table so resolve/publish can act immediately on boot instead of
  /// waiting for live announces to re-populate it. Returns how many were added.
  int seedPeers(Iterable<Uint8List> publicKeys) {
    final d = dht;
    if (d == null) return 0;
    var n = 0;
    for (final pub in publicKeys) {
      if (pub.length != 64) continue;
      try {
        d.routing.add(DhtContact.fromPublicKey(pub));
        n++;
      } catch (_) {/* skip a malformed key */}
    }
    return n;
  }

  /// Pull transport paths to [peer]'s DHT and files destinations (a cheap
  /// PATH_REQUEST per dest, which the peer's attached hub answers on our direct
  /// link) so the first resolve/fetch to it is routable WITHOUT waiting for a
  /// live announce to be flooded to us. Used by warm-start against cached peers.
  void requestPeerPaths(RnsIdentity peer) {
    final rp = requestPath;
    if (rp == null) return;
    rp(RnsDestination.hash(peer, kDhtApp, kDhtAspects));
    rp(RnsDestination.hash(peer, kFilesApp, kFilesAspects));
  }

  /// Number of confirmed Aurora DHT peers in the routing table (overlay
  /// membership). 0 means we've heard no other node's geogram/dht announce, so
  /// publish/resolve can only act locally — useful for diagnosing discovery.
  int get dhtRoutingSize => dht?.routing.size ?? 0;

  /// Identity hashes of the DHT peers in the routing table (debug: lets us see
  /// WHICH Aurora nodes are in the overlay, to diagnose discovery convergence).
  List<String> get dhtPeerHexes =>
      dht?.routing.contacts.map((c) => c.identity.hexHash).toList() ??
      const <String>[];

  /// Feed an inbound packet. Returns true if it was a file/link packet we
  /// consumed (so the caller can skip announce handling). Safe to call for every
  /// packet.
  Future<bool> handlePacket(RnsPacket p, {int arrivalHwMtu = kRnsMtu}) async {
    // 1) A peer opening a link to one of our destinations.
    if (p.packetType == RnsPacketType.linkRequest) {
      if (RnsCrypto.constantTimeEquals(p.destHash, filesDestHash)) {
        await _acceptLink(p, arrivalHwMtu);
        return true;
      }
      if (dht != null && RnsCrypto.constantTimeEquals(p.destHash, dhtDestHash)) {
        await _acceptDhtLink(p);
        return true;
      }
    }
    // 2) Traffic on an existing link (handshake proof, link data, resource).
    if (p.destType == RnsDestType.link) {
      final id = _hex(p.destHash);
      final serve = _serve[id];
      if (serve != null) {
        _onServePacket(serve, p);
        return true;
      }
      final fetch = _fetch[id];
      if (fetch != null) {
        await _onFetchPacket(fetch, p);
        return true;
      }
      final dep = _deposit[id];
      if (dep != null) {
        await _onDepositPacket(dep, p);
        return true;
      }
      final ds = _dhtServeLinks[id];
      if (ds != null) {
        await _onDhtServePacket(ds, p);
        return true;
      }
      final dr = _dhtRpcByLink[id];
      if (dr != null) {
        await _onDhtRpcPacket(dr, p);
        return true;
      }
    }
    return false;
  }

  // ── Serve side ─────────────────────────────────────────────────────────
  Future<void> _acceptLink(RnsPacket request, int arrivalHwMtu) async {
    try {
      final link =
          await RnsLink.responder(identity, request, arrivalHwMtu: arrivalHwMtu);
      final id = _hex(link.linkId!);
      _serve[id] = _ServeEntry(
        link,
        FileServeSession(link, source,
            quota: serveQuota,
            requesterId: id,
            onServed: onServed,
            onDepositOffer: onDepositOffer,
            onDepositStore: onDepositStore,
            log: log),
      );
      send((await link.buildProof()).pack());
      log?.call('files: accepted link $id');
    } catch (e) {
      log?.call('files: accept link failed: $e');
    }
  }

  void _onServePacket(_ServeEntry e, RnsPacket p) {
    if (e.link.status != RnsLinkStatus.active &&
        p.context == RnsContext.lrrtt) {
      e.link.handleRtt(p); // activate
      return;
    }
    for (final out in e.serve.onPacket(p)) {
      send(out.pack());
    }
  }

  // ── Fetch side ─────────────────────────────────────────────────────────
  /// Fetch [fileHash] (sha256, 32B) from [providerPublicIdentity] (learned from
  /// an announce). Returns the verified bytes, or null on failure/timeout.
  Future<Uint8List?> fetch(
    Uint8List fileHash,
    RnsIdentity providerPublicIdentity, {
    Duration timeout = const Duration(minutes: 20),
  }) async {
    // The link handshake (request -> proof -> RTT) can be lost over a lossy,
    // high-RTT cross-network path: the responder's LRPROOF in particular is sent
    // on all interfaces and a copy can be dropped before it returns. Re-sending
    // the SAME request is useless (RNS dedups by packet hash), so each retry
    // builds a FRESH link (new ephemeral key -> new link id -> new packet).
    // Once the handshake completes the transfer phase is single-interface and
    // reliable, so we only retry the handshake itself.
    const handshakeAttempts = 6;
    for (var attempt = 0; attempt < handshakeAttempts; attempt++) {
      final (result, handshakeOk) =
          await _fetchOnce(fileHash, providerPublicIdentity, timeout);
      // Got the bytes, or the handshake established and the transfer ran (and
      // failed for a real reason) — either way don't re-handshake.
      if (result != null || handshakeOk) return result;
      log?.call('files: handshake attempt ${attempt + 1} failed, retrying '
          '${_hex(fileHash)}');
    }
    return null;
  }

  /// One link-open + handshake + transfer attempt. Returns (bytesOrNull,
  /// handshakeCompleted) so [fetch] can decide whether to re-handshake.
  Future<(Uint8List?, bool)> _fetchOnce(
    Uint8List fileHash,
    RnsIdentity providerPublicIdentity,
    Duration timeout,
  ) async {
    final link =
        await RnsLink.initiator(providerPublicIdentity, kFilesApp, kFilesAspects);
    link.nextHop =
        await _ensurePath(providerPublicIdentity, kFilesApp, kFilesAspects);
    // Link MTU discovery: offer the next-hop interface's MTU so a TCP path
    // negotiates large resource parts (falls back to 500 with no callback).
    link.offerMtu(nextHopMtuForDest?.call(link.destHash) ?? kRnsMtu);
    log?.call('files: link offer mtu=${link.mtu} for ${_hex(link.destHash)}');
    final req = link.buildRequest();
    final entry = _FetchEntry(link, fileHash, Completer<Uint8List?>());
    entry.baseTimeout = timeout;
    final id = _hex(link.linkId!);
    _fetch[id] = entry;
    const tick = Duration(seconds: 4);
    // Per-attempt handshake budget (~32s); [fetch] retries with a fresh link.
    const maxHandshakeStalls = 8;
    // Once bytes are flowing, tolerate long no-progress gaps: over a lossy,
    // high-RTT cross-network path a healthy large transfer can go minutes
    // between visible byte advances (slow segment transitions, HMU round-trips,
    // a Wi-Fi blip). Reference RNS scales its part timeout by the link's
    // measured throughput; we approximate that with a generous fixed budget
    // (~5 min of dead air) and re-request every tick to drive recovery.
    const maxTransferStalls = 75;
    var lastSeen = -1;
    var stalls = 0;
    entry.retry = Timer.periodic(tick, (_) {
      final f = entry.fetch;
      if (f == null) {
        if (++stalls > maxHandshakeStalls && !entry.done.isCompleted) {
          entry.done.complete(null); // handshake never completed -> retry
        }
        return;
      }
      final got = f.receivedBytes;
      if (got != lastSeen) {
        lastSeen = got; // progress (any rate) — keep going
        stalls = 0;
        return;
      }
      // No byte progress this tick — log the receiver state to diagnose stalls.
      log?.call('fetch stall tick ${stalls + 1}: ${f.debugState}');
      if (++stalls > maxTransferStalls) {
        if (!entry.done.isCompleted) {
          log?.call('files: fetch stalled ($maxTransferStalls dead ticks) '
              '${_hex(fileHash)}');
          entry.done.complete(null);
        }
        return;
      }
      // Re-request the still-missing parts (retry() also shrinks the window).
      for (final out in f.retry()) {
        send(out.pack());
      }
    });
    send(req.pack());
    final result = await entry.done.future;
    entry.timeout?.cancel();
    entry.retry?.cancel();
    _fetch.remove(id);
    return (result, entry.fetch != null);
  }

  Future<void> _onFetchPacket(_FetchEntry e, RnsPacket p) async {
    // Handshake: validate the responder's proof, send LRRTT, start the fetch.
    if (e.fetch == null) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          _finishFetch(e, null, 'proof validation failed');
          return;
        }
        send(rtt.pack());
        final f = FileFetchSession(e.link, e.fileHash);
        e.fetch = f;
        send(f.start().pack());
      }
      return;
    }
    // Active: drive the fetch session.
    final f = e.fetch!;
    for (final out in f.onPacket(p)) {
      send(out.pack());
    }
    final got = f.receivedBytes;
    if (got > 0) {
      _fetchProgress[_hex(e.fileHash)] = (received: got, total: 0);
    }
    if (f.state == FileFetchState.done) {
      _finishFetch(e, f.result, null);
    } else if (f.state == FileFetchState.failed) {
      _finishFetch(e, null, f.error);
    }
  }

  void _finishFetch(_FetchEntry e, Uint8List? result, String? err) {
    if (err != null) log?.call('files: fetch failed: $err');
    _fetchProgress.remove(_hex(e.fileHash));
    if (!e.done.isCompleted) e.done.complete(result);
  }

  // ── Deposit side (ask a host to keep a blob) ───────────────────────────────
  final Map<String, _DepositEntry> _deposit = {}; // link_id hex -> deposit

  /// Deposit [bytes] (sha256 = [sha], extension [ext]) to [hostPublicIdentity]
  /// for store-and-forward hosting. [pub]/[sig] are the depositor's NOSTR x-only
  /// pubkey (32B) and a Schnorr signature over depositAuthMessageHex(shaHex) (64B)
  /// that authorizes hosting this blob. Returns true if the host stored it.
  Future<bool> deposit(
    Uint8List sha,
    Uint8List bytes,
    String ext,
    Uint8List pub,
    Uint8List sig,
    RnsIdentity hostPublicIdentity, {
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final link =
        await RnsLink.initiator(hostPublicIdentity, kFilesApp, kFilesAspects);
    link.nextHop =
        await _ensurePath(hostPublicIdentity, kFilesApp, kFilesAspects);
    final req = link.buildRequest();
    final entry = _DepositEntry(link, sha, bytes, ext, pub, sig, Completer<bool>());
    final id = _hex(link.linkId!);
    _deposit[id] = entry;
    entry.timeout = Timer(timeout, () {
      if (!entry.done.isCompleted) {
        log?.call('files: deposit timeout ${_hex(sha)}');
        entry.done.complete(false);
      }
    });
    send(req.pack());
    final ok = await entry.done.future;
    entry.timeout?.cancel();
    _deposit.remove(id);
    return ok;
  }

  Future<void> _onDepositPacket(_DepositEntry e, RnsPacket p) async {
    if (e.dep == null) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(false);
          return;
        }
        send(rtt.pack());
        final d =
            FileDepositSession(e.link, e.sha, e.bytes, e.ext, e.pub, e.sig);
        e.dep = d;
        send(d.start().pack());
      }
      return;
    }
    final d = e.dep!;
    for (final out in d.onPacket(p)) {
      send(out.pack());
    }
    if (d.state == FileDepositState.done) {
      if (!e.done.isCompleted) e.done.complete(true);
    } else if (d.state == FileDepositState.failed) {
      log?.call('files: deposit rejected: ${d.error}');
      if (!e.done.isCompleted) e.done.complete(false);
    }
  }

  // ── DHT over Reticulum links ───────────────────────────────────────────────
  /// Resolve providers for [sha256] via the DHT, then fetch the file from
  /// several of them in parallel (multi-source). Returns the verified bytes.
  /// Live download progress (received, total bytes) for an in-flight
  /// content-addressed fetch of [sha256], or null when nothing is downloading.
  ({int received, int total})? fetchProgress(Uint8List sha256) =>
      _fetchProgress[_hex(sha256)];

  /// Resolve providers for [sha256] via the DHT and fetch the whole file from the
  /// best available one over a single RNS Resource (the Resource layer segments,
  /// windows and HMUs it for arbitrary size). Falls back to the next provider on
  /// failure. Returns the sha-verified bytes, or null.
  Future<Uint8List?> resolveAndFetch(
    Uint8List sha256, {
    Duration timeout = const Duration(minutes: 20),
  }) async {
    final d = dht;
    if (d == null) return null;
    final providers = await d.resolve(sha256);
    log?.call('files: resolved ${providers.length} provider(s) for '
        '${_hex(sha256).substring(0, 8)}');
    final self = _hex(identity.hash);
    for (final pr in providers) {
      if (_hex(pr.providerIdentity.hash) == self) continue;
      final bytes = await fetch(sha256, pr.providerIdentity, timeout: timeout);
      if (bytes != null && bytes.isNotEmpty) return bytes;
    }
    return null;
  }

  /// Announce ourselves as a provider of [sha256] (auto-seed): publish a signed
  /// provider record at the k DHT nodes closest to the file key, and remember it
  /// for periodic republish. Returns how many holders accepted it.
  Future<int> publishProvider(
    Uint8List sha256, {
    int capacity = kCapUnknown,
    Uint8List? manifestHash,
  }) async {
    _provided[_hex(sha256)] =
        _Provided(Uint8List.fromList(sha256), capacity, manifestHash);
    return _publishOne(sha256, capacity, manifestHash);
  }

  /// Advertise ourselves as a provider of an arbitrary 32-byte DHT [key] (e.g. a
  /// folder id), independent of the file serve-quota — folders are metadata, not
  /// bulk bytes, so they should always be discoverable. Remembered for republish.
  Future<int> publishKey(Uint8List key, {int capacity = kCapUnknown}) async {
    final d = dht;
    if (d == null) return 0;
    _providedKeys[_hex(key)] = _Provided(Uint8List.fromList(key), capacity, null);
    final rec = await ProviderRecord.create(
        providerIdentity: identity, sha256: key, capacity: capacity);
    return d.publish(rec);
  }

  /// Resolve the provider node identities advertising a 32-byte [key] (folder id
  /// or sha256), best capacity first, excluding ourselves.
  Future<List<RnsIdentity>> resolveProviders(Uint8List key) async {
    final d = dht;
    if (d == null) return const [];
    final recs = await d.resolve(key);
    final self = _hex(identity.hash);
    return [
      for (final r in recs)
        if (_hex(r.providerIdentity.hash) != self) r.providerIdentity
    ];
  }

  /// Stop advertising [sha256] (let its record expire at TTL).
  void unpublishProvider(Uint8List sha256) => _provided.remove(_hex(sha256));

  int get providedCount => _provided.length;

  /// Re-publish all advertised files (refreshes TTL + re-stores at the current k
  /// closest nodes after churn). Drive from a periodic timer well under the TTL.
  Future<void> republishAll() async {
    for (final p in _provided.values.toList()) {
      await _publishOne(p.sha, p.capacity, p.manifestHash);
    }
    // Folder (and other ungated) keys advertise regardless of the serve-quota.
    final d = dht;
    if (d != null) {
      for (final p in _providedKeys.values.toList()) {
        final rec = await ProviderRecord.create(
            providerIdentity: identity, sha256: p.sha, capacity: p.capacity);
        await d.publish(rec);
      }
    }
    final n = _provided.length + _providedKeys.length;
    if (n > 0) log?.call('files: republished $n record(s)');
  }

  Future<int> _publishOne(Uint8List sha256, int capacity, Uint8List? manifestHash) async {
    final d = dht;
    if (d == null) return 0;
    // Don't advertise when we can't serve (off switch or daily budget spent) —
    // our records simply age out so resolvers route around us until we recover.
    if (!serveQuota.available) return 0;
    final rec = await ProviderRecord.create(
      providerIdentity: identity,
      sha256: sha256,
      capacity: capacity,
      manifestHash: manifestHash,
    );
    return d.publish(rec);
  }

  // DhtNode.sendRpc bridge: send a DHT message to a contact over a (transient)
  // link to its dht destination, await the single-packet reply.
  Future<DhtMessage?> _dhtSendRpc(DhtContact to, DhtMessage req) async {
    final respBytes = await _dhtRpcRaw(to.identity, req.encode());
    return respBytes == null ? null : DhtMessage.decode(respBytes);
  }

  Future<Uint8List?> _dhtRpcRaw(RnsIdentity peer, Uint8List reqBytes) async {
    final link = await RnsLink.initiator(peer, kDhtApp, kDhtAspects);
    link.nextHop = await _ensurePath(peer, kDhtApp, kDhtAspects);
    final reqPkt = link.buildRequest();
    final id = _hex(link.linkId!);
    final e = _DhtRpcEntry(link, reqBytes);
    _dhtRpcByLink[id] = e;
    send(reqPkt.pack());
    final resp = await e.done.future
        .timeout(const Duration(seconds: 8), onTimeout: () => null);
    _dhtRpcByLink.remove(id);
    return resp;
  }

  Future<void> _acceptDhtLink(RnsPacket request) async {
    try {
      final link = await RnsLink.responder(identity, request);
      final id = _hex(link.linkId!);
      _dhtServeLinks[id] = link;
      _dhtServeOrder.add(id);
      if (_dhtServeOrder.length > _maxDhtServeLinks) {
        _dhtServeLinks.remove(_dhtServeOrder.removeAt(0));
      }
      send((await link.buildProof()).pack());
    } catch (e) {
      log?.call('dht: accept link failed: $e');
    }
  }

  Future<void> _onDhtServePacket(RnsLink link, RnsPacket p) async {
    if (link.status != RnsLinkStatus.active && p.context == RnsContext.lrrtt) {
      link.handleRtt(p);
      return;
    }
    if (p.context == RnsContext.none) {
      final reqBytes = link.decrypt(p);
      final respBytes = await dht?.handleEncoded(reqBytes);
      if (respBytes != null) {
        send(link.encrypt(respBytes, context: RnsContext.none).pack());
      }
    }
  }

  Future<void> _onDhtRpcPacket(_DhtRpcEntry e, RnsPacket p) async {
    if (!e.sent) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(null);
          return;
        }
        send(rtt.pack());
        send(e.link.encrypt(e.reqBytes, context: RnsContext.none).pack());
        e.sent = true;
      }
      return;
    }
    if (p.context == RnsContext.none && !e.done.isCompleted) {
      e.done.complete(e.link.decrypt(p));
    }
  }

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}
