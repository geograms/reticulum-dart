/*
 * NostrRelayHub — the one place that manages a user's relay LIST and fans NOSTR
 * traffic across every transport. The wapp/UI talks only to the hub: it manages
 * a list of relay URIs (add/remove, see status) and calls subscribe/publish. The
 * hub picks the transport per URI scheme (wss:// | rns:// | local), merges every
 * inbound event into the ONE local RelayEventStore (verify + dedup), and buffers
 * per-subscription events for the wapp to drain (inbox-pop, the established HAL
 * pattern). Adding a transport = one client class; nothing here changes.
 *
 * The relay list is persisted as JSON so it survives restarts and is
 * pre-populated with common relays on first run.
 */
import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import '../../util/nostr_event.dart';
import 'nostr_local_client.dart';
import 'nostr_relay_client.dart';
import 'nostr_wire.dart';
import 'nostr_ws_client.dart';
import 'relay_event_store.dart';

/// The slice of an event store the hub needs — put + query. `RelayEventStore`
/// satisfies it via [NostrStore.of]; tests use an in-memory fake so the hub is
/// exercisable without the sqlite native library.
abstract class NostrStore {
  bool put(NostrEvent e, {int tier});
  List<NostrEvent> query(NostrFilter f);

  factory NostrStore.of(RelayEventStore s) = _RelayEventStoreAdapter;
}

class _RelayEventStoreAdapter implements NostrStore {
  final RelayEventStore store;
  _RelayEventStoreAdapter(this.store);
  @override
  bool put(NostrEvent e, {int tier = 2}) => store.put(e, tier: tier);
  @override
  List<NostrEvent> query(NostrFilter f) => store.query(f);
}

/// Common public relays pre-populated on first run, plus the device itself.
const List<String> kDefaultNostrRelays = [
  'local', // this device (RelayEventStore, also served over RNS + wss)
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
  'wss://relay.primal.net',
  'wss://purplepag.es',
];

class NostrRelayEndpoint {
  final String uri;
  bool enabled;
  NostrRelayEndpoint(this.uri, {this.enabled = true});

  NostrTransport get transport => nostrTransportOf(uri);

  Map<String, dynamic> toJson() => {'uri': uri, 'enabled': enabled};
  factory NostrRelayEndpoint.fromJson(Map<String, dynamic> j) =>
      NostrRelayEndpoint('${j['uri']}', enabled: j['enabled'] != false);
}

class NostrRelayHub {
  final NostrStore store;
  final void Function(String msg)? log;

  /// Where to persist the relay list (JSON). Null = in-memory only (tests).
  final String? persistPath;

  /// Builds a client for an `rns://…` endpoint (aurora resolves the hash to an
  /// RnsIdentity + RelayNode). ws:// and local are built by the hub itself.
  final NostrRelayClient? Function(String uri)? rnsClientFactory;

  /// Called after any event is merged into the store — the device's own wss
  /// server hooks this to LIVE-push mesh/internet events to LAN subscribers.
  final void Function(NostrEvent event)? onStored;

  final Map<String, NostrRelayEndpoint> _endpoints = {};
  final Map<String, NostrRelayClient> _clients = {};

  // Per-subscription: the active filters, a bounded inbox the wapp drains, and a
  // seen-id set so the same event from several relays is delivered once.
  final Map<String, List<NostrFilter>> _subFilters = {};
  final Map<String, Queue<NostrEvent>> _inbox = {};
  final Map<String, Set<String>> _seen = {};
  static const int _maxInbox = 500;

  int _subSeq = 0;

  NostrRelayHub({
    required this.store,
    this.persistPath,
    this.rnsClientFactory,
    this.onStored,
    this.log,
  });

  // ── Relay list ────────────────────────────────────────────────────────────

  /// Load persisted relays, or seed the defaults on first run.
  Future<void> init() async {
    final loaded = _load();
    if (loaded.isEmpty) {
      for (final u in kDefaultNostrRelays) {
        _endpoints[u] = NostrRelayEndpoint(u);
      }
      _save();
    } else {
      for (final e in loaded) {
        _endpoints[e.uri] = e;
      }
    }
    for (final e in _endpoints.values) {
      _ensureClient(e.uri);
    }
  }

  List<NostrRelayEndpoint> _load() {
    final p = persistPath;
    if (p == null) return const [];
    try {
      final f = File(p);
      if (!f.existsSync()) return const [];
      final j = jsonDecode(f.readAsStringSync());
      if (j is! List) return const [];
      return [
        for (final e in j)
          if (e is Map)
            NostrRelayEndpoint.fromJson(e.map((k, v) => MapEntry('$k', v)))
      ];
    } catch (e) {
      log?.call('relay list load failed: $e');
      return const [];
    }
  }

  void _save() {
    final p = persistPath;
    if (p == null) return;
    try {
      File(p).writeAsStringSync(
          jsonEncode([for (final e in _endpoints.values) e.toJson()]));
    } catch (e) {
      log?.call('relay list save failed: $e');
    }
  }

  /// Relay list + live status for the UI panel.
  List<Map<String, dynamic>> relaysJson() => [
        for (final e in _endpoints.values)
          {
            'uri': e.uri,
            'scheme': e.transport.name,
            'enabled': e.enabled,
            'status':
                (_clients[e.uri]?.status ?? NostrRelayStatus.disconnected).name,
          }
      ];

  /// Add a relay by URI. Returns false if the scheme is unknown or duplicate.
  bool addRelay(String uri) {
    final u = uri.trim();
    if (u.isEmpty || nostrTransportOf(u) == NostrTransport.unknown) return false;
    if (_endpoints.containsKey(u)) return false;
    _endpoints[u] = NostrRelayEndpoint(u);
    _save();
    final c = _ensureClient(u);
    // Backfill the new relay with every live subscription.
    if (c != null) {
      for (final e in _subFilters.entries) {
        c.subscribe(e.key, e.value);
      }
    }
    return true;
  }

  bool removeRelay(String uri) {
    final e = _endpoints.remove(uri);
    if (e == null) return false;
    _save();
    // ignore: discarded_futures
    _clients.remove(uri)?.close();
    return true;
  }

  NostrRelayClient? _ensureClient(String uri) {
    final existing = _clients[uri];
    if (existing != null) return existing;
    final NostrRelayClient? c;
    switch (nostrTransportOf(uri)) {
      case NostrTransport.local:
        c = NostrLocalClient(store, uri: uri);
      case NostrTransport.websocket:
        c = NostrWsClient(uri, log: log);
      case NostrTransport.reticulum:
        c = rnsClientFactory?.call(uri);
      case NostrTransport.unknown:
        c = null;
    }
    if (c == null) return null;
    c.onEvent = _onEvent;
    c.onEose = (_) {};
    c.onStatus = (_) {};
    _clients[uri] = c;
    // ignore: discarded_futures
    c.connect();
    return c;
  }

  // ── Subscribe / publish ────────────────────────────────────────────────────

  /// Open a subscription across every enabled relay. Returns a subId the wapp
  /// uses to [drainEvents]. Also answers immediately from the local store.
  String subscribe(List<NostrFilter> filters) =>
      subscribeWithId('h${_subSeq++}', filters);

  /// As [subscribe] but with a caller-supplied id (the off-isolate engine mints
  /// ids on the main side and passes them through).
  String subscribeWithId(String subId, List<NostrFilter> filters) {
    _subFilters[subId] = filters;
    _inbox[subId] = Queue<NostrEvent>();
    _seen[subId] = <String>{};
    for (final e in _endpoints.values) {
      if (!e.enabled) continue;
      _clients[e.uri]?.subscribe(subId, filters);
    }
    return subId;
  }

  void unsubscribe(String subId) {
    _subFilters.remove(subId);
    _inbox.remove(subId);
    _seen.remove(subId);
    for (final c in _clients.values) {
      c.unsubscribe(subId);
    }
  }

  // ── Discovery feed (for users who follow nobody) ────────────────────────────
  // A raw kind-1 firehose is mostly spam/repeats. Instead we watch the kind-7
  // REACTION firehose, tally distinct likers per event, and only surface a post
  // once it has crossed a like threshold — then fetch that specific note by id.
  // Spam gets no reactions, so it never appears.
  String? _discoFeedSub; // the subId the wapp drains
  String? _discoReactSub; // internal kind-7 subscription
  int _discoMinLikes = 3;
  final Map<String, Set<String>> _discoLikers = {}; // eventId → distinct likers
  final Set<String> _discoWanted = {}; // ids past the threshold
  final Set<String> _discoFetched = {}; // ids already requested
  final List<String> _discoToFetch = []; // newly wanted, awaiting a REQ
  Timer? _discoTimer;

  /// Ids of posts we count engagement for, and pubkeys we resolve profiles for
  /// (the off-isolate engine polls these to build its snapshots).
  Iterable<String> get trackedStatIds => _statTracked;
  Iterable<String> get trackedProfilePubs => _profTracked;

  /// Start (or return) the discovery feed: a subId that only receives kind-1
  /// posts which have gathered at least [minLikes] distinct reactions.
  String subscribeDiscovery({int minLikes = 3}) =>
      subscribeDiscoveryWithId('disco${_subSeq++}', minLikes: minLikes);

  String subscribeDiscoveryWithId(String feed, {int minLikes = 3}) {
    final existing = _discoFeedSub;
    if (existing != null) return existing;
    _discoMinLikes = minLikes;
    _discoFeedSub = feed;
    _inbox[feed] = Queue<NostrEvent>();
    _seen[feed] = <String>{};
    // Internal reactions subscription — tallied, never drained by the wapp.
    final react = 'discoR${_subSeq++}';
    _discoReactSub = react;
    final rf = [const NostrFilter(kinds: [7], limit: 500)];
    _subFilters[react] = rf;
    _inbox[react] = Queue<NostrEvent>();
    _seen[react] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(react, rf);
    }
    _discoTimer ??=
        Timer.periodic(const Duration(seconds: 3), (_) => _discoFetch());
    return feed;
  }

  void _discoFetch() {
    if (_discoToFetch.isEmpty) return;
    final batch = <String>[];
    while (_discoToFetch.isNotEmpty && batch.length < 100) {
      batch.add(_discoToFetch.removeAt(0));
    }
    final sub = 'discoF${_subSeq++}';
    final f = [NostrFilter(ids: batch, kinds: const [1])];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  static String? _firstETag(NostrEvent e) {
    for (final t in e.tags) {
      if (t.length >= 2 && t[0] == 'e') return t[1];
    }
    return null;
  }

  /// Fold a reaction into the like tally; returns true if this was a reaction
  /// (so the caller skips normal store/buffer work for it).
  bool _discoTally(NostrEvent event) {
    if (_discoFeedSub == null || event.kind != NostrEventKind.reaction) {
      return false;
    }
    final liked = _firstETag(event);
    if (liked == null) return true;
    final likers = _discoLikers.putIfAbsent(liked, () => <String>{});
    likers.add(event.pubkey);
    if (likers.length >= _discoMinLikes && _discoFetched.add(liked)) {
      _discoWanted.add(liked);
      _discoToFetch.add(liked);
    }
    // Bound the tally map: forget the least-liked once it grows too large.
    if (_discoLikers.length > 8000) {
      final weak =
          _discoLikers.entries.where((e) => e.value.length < 2).map((e) => e.key).take(2000);
      for (final k in weak.toList()) {
        _discoLikers.remove(k);
      }
    }
    return true;
  }

  // ── Engagement stats (likes + replies per visible post) ─────────────────────
  final Map<String, Set<String>> _statReact = {}; // eventId → reactor pubkeys
  final Map<String, Set<String>> _statReply = {}; // eventId → reply event ids
  final List<String> _statTracked = []; // rolling set of ids we count for
  String? _statSub;
  Timer? _statDebounce;

  /// Count reactions (kind-7) and replies (kind-1 with #e) for [ids] by
  /// subscribing to events that reference them. The feed calls this with the
  /// post ids currently on screen; a rolling window keeps the REQ bounded.
  void trackStats(List<String> ids) {
    var added = false;
    for (final id in ids) {
      if (id.length != 64 || _statReact.containsKey(id)) continue;
      _statTracked.add(id);
      _statReact[id] = <String>{};
      _statReply[id] = <String>{};
      added = true;
    }
    while (_statTracked.length > 300) {
      final old = _statTracked.removeAt(0);
      _statReact.remove(old);
      _statReply.remove(old);
    }
    if (added) {
      // Debounce: the feed adds ids in bursts as the user scrolls.
      _statDebounce?.cancel();
      _statDebounce = Timer(const Duration(milliseconds: 700), _statResub);
    }
  }

  void _statResub() {
    if (_statTracked.isEmpty) return;
    final prev = _statSub;
    if (prev != null) {
      _subFilters.remove(prev);
      _inbox.remove(prev);
      _seen.remove(prev);
      for (final c in _clients.values) {
        c.unsubscribe(prev);
      }
    }
    final ids = List<String>.from(_statTracked);
    final sub = 'stat${_subSeq++}';
    _statSub = sub;
    final f = [
      NostrFilter(kinds: const [7], tags: {'e': ids}),
      NostrFilter(kinds: const [1], tags: {'e': ids}),
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  /// Record a reaction/reply against a tracked post. Returns true if it was an
  /// engagement event for a tracked post (so the caller skips normal handling).
  bool _tallyStats(NostrEvent event) {
    final ref = _firstETag(event);
    if (ref == null) return false;
    if (event.kind == NostrEventKind.reaction) {
      final s = _statReact[ref];
      if (s != null) s.add(event.pubkey);
      return true; // reactions are never displayed
    }
    if (event.kind == NostrEventKind.textNote) {
      final s = _statReply[ref];
      if (s != null && event.id != null) s.add(event.id!);
      // a reply is still a note; let it flow on for storage/threading
    }
    return false;
  }

  /// (likes, replies, likedByMe) for a post id.
  (int, int, bool) statsOf(String id, String? selfPub) {
    final r = _statReact[id];
    final mine = selfPub != null && (r?.contains(selfPub) ?? false);
    return (r?.length ?? 0, _statReply[id]?.length ?? 0, mine);
  }

  /// Optimistically record our own like so the count updates before it round-
  /// trips back from a relay.
  void recordReaction(String id, String pub) {
    (_statReact[id] ??= <String>{}).add(pub);
    if (!_statTracked.contains(id)) _statTracked.add(id);
  }

  // ── Profiles (kind-0 metadata for post authors) ─────────────────────────────
  final List<String> _profTracked = []; // rolling set of author pubkeys
  final Set<String> _profSeen = {};
  String? _profSub;
  Timer? _profDebounce;

  /// Ensure we subscribe to (and thus store) the kind-0 profile for [pub]. Safe
  /// to call repeatedly; a rolling window keeps the REQ bounded.
  void trackProfile(String pub) {
    if (pub.length != 64 || !_profSeen.add(pub)) return;
    _profTracked.add(pub);
    while (_profTracked.length > 500) {
      _profSeen.remove(_profTracked.removeAt(0));
    }
    _profDebounce?.cancel();
    _profDebounce = Timer(const Duration(milliseconds: 700), _profResub);
  }

  void _profResub() {
    if (_profTracked.isEmpty) return;
    final prev = _profSub;
    if (prev != null) {
      _subFilters.remove(prev);
      _inbox.remove(prev);
      _seen.remove(prev);
      for (final c in _clients.values) {
        c.unsubscribe(prev);
      }
    }
    final sub = 'prof${_subSeq++}';
    _profSub = sub;
    final f = [
      NostrFilter(kinds: const [0], authors: List<String>.from(_profTracked))
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  /// Stored kind-1 replies to [postId] (events that #e it), oldest first.
  List<NostrEvent> repliesTo(String postId) {
    final evs = store.query(NostrFilter(kinds: const [1], tags: {'e': [postId]}));
    final out = evs
        .where((e) => e.tags
            .any((t) => t.length >= 2 && t[0] == 'e' && t[1] == postId))
        .toList()
      ..sort((a, b) => a.createdAt.compareTo(b.createdAt));
    return out;
  }

  /// The latest stored kind-0 profile event for [pub], if any.
  NostrEvent? profileOf(String pub) {
    final evs = store.query(NostrFilter(kinds: const [0], authors: [pub]));
    NostrEvent? best;
    for (final e in evs) {
      if (best == null || e.createdAt > best.createdAt) best = e;
    }
    return best;
  }

  // Delivery rate cap: bounds the SQLite/dispatch work this (UI/engine) isolate
  // does per second, so a public firehose is SAMPLED instead of flooding the
  // main thread. A followed/web-of-trust feed is low-volume and never trips it.
  static const int _rateWindowMs = 250;
  static const int _rateMaxPerWindow = 15; // ~60 events/s ceiling (main-thread SQLite)
  int _rateWindowStart = 0;
  int _rateCount = 0;
  int rateDropped = 0;

  void _onEvent(String subId, NostrEvent event) {
    // Engagement (likes/replies) is tallied for on-screen posts BEFORE the rate
    // cap so counts stay accurate. Reactions are tally-only (never displayed).
    final wasReaction = _tallyStats(event);
    // Reactions also drive the discovery tally; both consume the reaction here.
    if (_discoTally(event)) return;
    if (wasReaction) return;

    final now = DateTime.now().millisecondsSinceEpoch;
    if (now - _rateWindowStart >= _rateWindowMs) {
      _rateWindowStart = now;
      _rateCount = 0;
    }
    if (_rateCount >= _rateMaxPerWindow) {
      rateDropped++; // firehose overflow — dropped before any main-thread work
      return;
    }
    _rateCount++;
    // Merge into the unified store (dedup + replaceable/deletion handled there).
    if (store.put(event)) onStored?.call(event);
    // A liked-enough post (fetched by id) goes to the discovery feed too.
    if (_discoFeedSub != null &&
        event.kind == NostrEventKind.textNote &&
        event.id != null &&
        _discoWanted.contains(event.id)) {
      _bufferForSub(_discoFeedSub!, event);
    }
    _bufferForSub(subId, event);
    final seen = _seen[subId];
    if (seen != null && seen.length > _maxInbox * 4) seen.clear();
  }

  /// Pop up to [max] buffered events for a subscription (oldest first), as JSON.
  /// Empty when the inbox is drained — the wapp polls this each tick.
  List<Map<String, dynamic>> drainEvents(String subId, {int max = 50}) {
    final inbox = _inbox[subId];
    if (inbox == null) return const [];
    final out = <Map<String, dynamic>>[];
    while (inbox.isNotEmpty && out.length < max) {
      out.add(inbox.removeFirst().toJson());
    }
    return out;
  }

  /// Publish an event to the local store + every enabled relay. Our own event
  /// is also surfaced to matching open subscriptions so the feed shows it
  /// immediately (it won't arrive back over a relay for a moment).
  Future<void> publish(NostrEvent event) async {
    if (store.put(event, tier: 0)) onStored?.call(event);
    for (final e in _subFilters.entries) {
      if (e.value.any((f) => NostrWire.matches(f, event))) {
        _bufferForSub(e.key, event);
      }
    }
    for (final e in _endpoints.values) {
      if (!e.enabled) continue;
      // ignore: discarded_futures
      _clients[e.uri]?.publish(event);
    }
  }

  void _bufferForSub(String subId, NostrEvent event) {
    final inbox = _inbox[subId];
    final seen = _seen[subId];
    if (inbox == null || seen == null || event.id == null) return;
    if (!seen.add(event.id!)) return;
    inbox.add(event);
    while (inbox.length > _maxInbox) {
      inbox.removeFirst();
    }
  }

  Future<void> close() async {
    _discoTimer?.cancel();
    _discoTimer = null;
    _statDebounce?.cancel();
    _statDebounce = null;
    _profDebounce?.cancel();
    _profDebounce = null;
    for (final c in _clients.values) {
      await c.close();
    }
    _clients.clear();
  }
}
