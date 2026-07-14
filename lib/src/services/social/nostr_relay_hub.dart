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
import 'feed_quality.dart';
import 'nostr_local_client.dart';
import 'nostr_relay_client.dart';
import 'nostr_wire.dart';
import 'nostr_ws_client.dart';
import 'relay_event_store.dart';

/// How often we go BACK to the relays for new posts.
///
/// Not a freshness knob — a battery knob. The wss relays PUSH events over a live
/// subscription, so nothing here delays a post from a relay that is connected;
/// this governs the polls we make ourselves (the Reticulum relay re-query, and
/// the discovery-feed fetch). Those used to run every 30s and every 3s
/// respectively, on a phone that is usually in a pocket with the screen off and
/// nobody reading the feed.
///
/// Each poll is preceded by an immediate first fetch, so a cold start still
/// fills the feed at once — the interval only governs how often we go back.
const Duration kNostrPollInterval = Duration(minutes: 10);

/// The slice of an event store the hub needs — put + query. `RelayEventStore`
/// satisfies it via [NostrStore.of]; tests use an in-memory fake so the hub is
/// exercisable without the sqlite native library.
abstract class NostrStore {
  bool put(NostrEvent e, {int tier});
  List<NostrEvent> query(NostrFilter f);

  // Persisted engagement — reaction receipts survive restarts so like/reply
  // tallies load instantly instead of crawling back over the network. The
  // defaults are no-ops so in-memory test fakes need not care.
  bool addReaction(String eventId, String pubkey) => false;
  List<String> reactionPubkeys(String eventId) => const [];
  List<String> replyIdsFor(String eventId) => const [];

  factory NostrStore.of(RelayEventStore s) = _RelayEventStoreAdapter;
}

class _RelayEventStoreAdapter implements NostrStore {
  final RelayEventStore store;
  _RelayEventStoreAdapter(this.store);
  @override
  bool put(NostrEvent e, {int tier = 2}) => store.put(e, tier: tier);
  @override
  List<NostrEvent> query(NostrFilter f) => store.query(f);
  @override
  bool addReaction(String eventId, String pubkey) =>
      store.addReaction(eventId, pubkey);
  @override
  List<String> reactionPubkeys(String eventId) =>
      store.reactionPubkeys(eventId);
  @override
  List<String> replyIdsFor(String eventId) => store.replyIdsFor(eventId);
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

  /// The relays this device is offered if it has never been offered them before.
  /// Injectable so a test can run the hub with no public relays (and therefore
  /// no real sockets).
  final List<String> defaultRelays;

  NostrRelayHub({
    required this.store,
    this.persistPath,
    this.rnsClientFactory,
    this.onStored,
    this.log,
    this.defaultRelays = kDefaultNostrRelays,
  });

  // ── Relay list ────────────────────────────────────────────────────────────

  /// Load persisted relays, and offer any default this device has never been
  /// offered before.
  ///
  /// Seeding the defaults ONLY on first run is how a device ends up stranded: the
  /// persisted list shadows the constant forever, so a relay added to the
  /// defaults later never reaches an existing install, and a list whose relays
  /// have since died stays dead. A phone was found running on two relays — one
  /// unreachable, one that answers no firehose — with a feed sixteen hours old.
  ///
  /// A default the user has REMOVED is not re-added: [_offered] remembers every
  /// default this device has ever been given, so "never offered" and "offered
  /// and thrown away" are different things. Disabled stays disabled too.
  Future<void> init() async {
    final loaded = _load();
    for (final e in loaded) {
      _endpoints[e.uri] = e;
    }
    var added = 0;
    for (final u in defaultRelays) {
      if (_offered.contains(u)) continue; // offered before; user's call now
      _offered.add(u);
      if (_endpoints.containsKey(u)) continue;
      _endpoints[u] = NostrRelayEndpoint(u);
      added++;
    }
    if (added > 0 || loaded.isEmpty) {
      log?.call('relays: added $added default(s), ${_endpoints.length} total');
      _save();
    }
    for (final e in _endpoints.values) {
      _ensureClient(e.uri);
    }
  }

  /// Every default relay this device has ever been offered (persisted next to
  /// the list itself). Without it, "the user removed this one" is
  /// indistinguishable from "this one is new", and a merge would resurrect what
  /// the user threw away on every single start.
  final Set<String> _offered = {};

  List<NostrRelayEndpoint> _load() {
    final p = persistPath;
    if (p == null) return const [];
    try {
      final f = File(p);
      if (!f.existsSync()) return const [];
      final j = jsonDecode(f.readAsStringSync());
      // Two shapes: the original bare list, and the current object that also
      // carries which defaults this device has already been offered. An old
      // file simply has no memory of what it was offered — every relay in it
      // counts as offered, so an upgrade adds the defaults it never had and
      // resurrects nothing.
      final List<dynamic> list;
      if (j is List) {
        list = j;
        for (final e in list) {
          if (e is Map && e['uri'] != null) _offered.add('${e['uri']}');
        }
      } else if (j is Map && j['relays'] is List) {
        list = j['relays'] as List;
        for (final u in (j['offered'] as List? ?? const [])) {
          _offered.add('$u');
        }
      } else {
        return const [];
      }
      return [
        for (final e in list)
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
      File(p).writeAsStringSync(jsonEncode({
        'relays': [for (final e in _endpoints.values) e.toJson()],
        'offered': _offered.toList(),
      }));
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

  /// Turn a relay on or off without forgetting it. Off means: no subscriptions,
  /// no publishes, no connection — but it stays in the list, so a relay that is
  /// down (or that you simply do not want to talk to right now) does not have to
  /// be re-typed later.
  bool setRelayEnabled(String uri, bool enabled) {
    final e = _endpoints[uri];
    if (e == null || e.enabled == enabled) return false;
    e.enabled = enabled;
    _save();
    if (enabled) {
      final c = _ensureClient(uri);
      for (final f in _subFilters.entries) {
        c?.subscribe(f.key, f.value);
      }
    } else {
      final c = _clients.remove(uri);
      // ignore: discarded_futures
      c?.close();
    }
    return true;
  }

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
    // A refused subscription is not an error anywhere else in the stack: the
    // socket stays up and the events simply never come. Name it.
    c.onClosed =
        (subId, message) => log?.call('relay $uri refused $subId: $message');
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

    // A discovery subscriber leaving must not leave the machinery pointing at a
    // dead inbox. This is what made pull-to-refresh (unsubscribe → re-subscribe)
    // kill the discovery feed for the life of the process: _discoFeedSub still
    // named the id we had just deleted, so every qualifying post was buffered
    // into nothing and the re-subscribe was handed the same corpse.
    if (_discoSubscribers.remove(subId) && _discoSubscribers.isEmpty) {
      _teardownDiscovery();
    }
    if (_fireSubscribers.remove(subId) && _fireSubscribers.isEmpty) {
      _teardownFirehose();
    }
  }

  void _teardownDiscovery() {
    _discoFeedSub = null;
    final react = _discoReactSub;
    _discoReactSub = null;
    if (react != null) {
      _subFilters.remove(react);
      _inbox.remove(react);
      _seen.remove(react);
      for (final c in _clients.values) {
        c.unsubscribe(react);
      }
    }
    _discoTimer?.cancel();
    _discoTimer = null;
    _discoPrime?.cancel();
    _discoPrime = null;
    _discoPrimed = false;
  }

  // ── Discovery feed (for users who follow nobody) ────────────────────────────
  // A raw kind-1 firehose is mostly spam/repeats. Instead we watch the kind-7
  // REACTION firehose, tally distinct likers per event, and only surface a post
  // once it has crossed a like threshold — then fetch that specific note by id.
  // Spam gets no reactions, so it never appears.
  String? _discoFeedSub; // the internal feed the qualifying posts land in
  String? _discoReactSub; // internal kind-7 subscription

  /// Everyone drinking from the discovery feed.
  ///
  /// There is more than one: the launcher hero subscribes at startup and the
  /// Social wapp subscribes when it opens. The old code returned the FIRST
  /// subscriber's id to everybody and never created an inbox for the others, so
  /// the second subscriber drained an id the hub would never fill — silently,
  /// forever. Whoever asked second simply got no feed.
  final Set<String> _discoSubscribers = {};
  int _discoMinLikes = 2;
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
  String subscribeDiscovery({int minLikes = 2}) =>
      subscribeDiscoveryWithId('disco${_subSeq++}', minLikes: minLikes);

  String subscribeDiscoveryWithId(String feed, {int minLikes = 2}) {
    // EVERY subscriber gets its own inbox. Handing them all one shared id (what
    // this used to do) meant the second one drained a queue that did not exist.
    _discoSubscribers.add(feed);
    _inbox[feed] = Queue<NostrEvent>();
    _seen[feed] = <String>{};

    final existing = _discoFeedSub;
    if (existing != null) return feed; // machinery already running

    _discoMinLikes = minLikes;
    _discoFeedSub = feed;
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
    // Fetch NOW so the feed fills immediately, then settle into a slow poll.
    //
    // This used to re-poll every 3 SECONDS. Nobody needs a discovery feed that
    // fresh: the phone is usually in a pocket with the screen off, and a poll
    // interval is a battery setting, not a freshness setting. Ten minutes.
    if (_discoTimer == null) {
      _discoFetch();
      _discoTimer = Timer.periodic(kNostrPollInterval, (_) => _discoFetch());
    }
    return feed;
  }

  // ── The live firehose (the "All" tab) ──────────────────────────────────────
  //
  // Discovery (above) can only ever surface a post that has ALREADY collected
  // likes — it watches reactions and then fetches the post by id. That makes it
  // a "popular" feed, and it is fine for that, but it was also being used as the
  // All tab, where it guarantees the newest thing on screen is an hour old.
  //
  // This is the actual firehose: a plain live kind-1 subscription that the
  // relays PUSH to us, sub-second. What makes it usable rather than a sewer is
  // the quality gate (feed_quality.dart) — and what makes the STRICT gate
  // possible is that we ask for kind-0 in the same breath, so the authors
  // posting right now are exactly the authors whose profiles arrive.

  String? _fireSub; // the internal relay subscription
  final Set<String> _fireSubscribers = {}; // ids the wapp/host drains
  FirehoseFilter? _fireFilter;

  /// Pubkeys we have a kind-0 for. An in-memory set, not a store query: the gate
  /// runs on EVERY firehose event, and a sqlite round-trip per post is exactly
  /// the kind of per-item work that turns the engine isolate into a hot core.
  /// Misses are memoized too — on a public firehose most authors are unknown,
  /// and a cache that only remembers hits re-queries them forever
  /// (aurora/docs/performance.md §3.2).
  final Set<String> _haveProfile = {};
  final Set<String> _noProfile = {};

  /// Self + everyone we follow: they bypass the gate entirely. Pushed in by the
  /// main isolate, which owns the authoritative follow set.
  Set<String> trustedAuthors = {};

  /// My own pubkey. Everything I write, and everything ANYONE writes ABOUT me,
  /// is kept in the local store at tier `self` — see [_isMine].
  String? selfPubkey;

  /// Authors the user muted.
  ///
  /// Matched on the **12-char author key** (the first 12 hex chars of the
  /// pubkey) as well as the full key, because that is what the feed shows on a
  /// post and therefore what the user is actually pointing at when they mute.
  /// Case-insensitive: the host keys upper, the wire is lower.
  ///
  /// A muted author is rejected by the gate BEFORE the post is stored. Muting is
  /// not a display filter — it is a refusal to carry.
  Set<String> mutedAuthors = {};

  bool _isMuted(String pub) {
    if (mutedAuthors.isEmpty) return false;
    final up = pub.toUpperCase();
    if (mutedAuthors.contains(up) || mutedAuthors.contains(pub)) return true;
    if (up.length < 12) return false;
    return mutedAuthors.contains(up.substring(0, 12));
  }

  String subscribeFirehose({bool requireProfile = true}) =>
      subscribeFirehoseWithId('fire${_subSeq++}', requireProfile: requireProfile);

  String subscribeFirehoseWithId(String subId, {bool requireProfile = true}) {
    _fireSubscribers.add(subId);
    _inbox[subId] = Queue<NostrEvent>();
    _seen[subId] = <String>{};
    _fireFilter ??= FirehoseFilter(requireProfile: requireProfile);

    if (_fireSub != null) return subId; // relay subscription already open

    _openFirehoseReq();
    // Watchdog. A relay caps how many subscriptions one connection may hold and
    // silently drops the excess — and we hold a lot of them (profiles, stats,
    // reactions, web-of-trust, search…), several of which churn their ids. The
    // firehose was observed going quiet after its first burst for exactly this
    // reason: nobody had closed it, the relay had just stopped answering it.
    // There is no error to catch, so the only honest signal is silence.
    _fireWatchdog ??= Timer.periodic(const Duration(seconds: 30), (_) {
      if (_fireSub == null) return;
      final now = DateTime.now().millisecondsSinceEpoch;
      if (now - _fireLastEventMs < _fireSilenceMs) return;
      // Say WHO is supposed to be answering. A bare "re-opening" every minute
      // reads like a retry that is about to work; the truth was that no relay
      // capable of serving a firehose was connected at all, and the feed had
      // been sixteen hours stale for exactly that reason.
      final live = [
        for (final e in _endpoints.values)
          if (e.enabled &&
              _clients[e.uri]?.status == NostrRelayStatus.connected)
            e.uri,
      ];
      _fireSilentRounds++;
      log?.call('firehose: silent for ${_fireSilenceMs ~/ 1000}s — re-opening '
          '(connected: ${live.isEmpty ? "NONE" : live.join(", ")})');
      _closeFirehoseReq();
      _openFirehoseReq();

      // Twice in a row means the REQ is not the problem. A relay that has
      // quietly dropped this subscription — no CLOSED, no error, the socket
      // still carrying our other subs — will keep ignoring it however many
      // times we ask down the same connection. Only a new connection is
      // answered, and reconnecting replays every subscription we hold.
      if (_fireSilentRounds >= 2) {
        _fireSilentRounds = 0;
        for (final uri in live) {
          _clients[uri]?.reconnect();
        }
      }
    });
    // Ask for the held authors' profiles in one small batch, slowly. This is a
    // background chore, not a hot path: the posts are already held, and a REQ
    // storm is what got us dropped by the relays in the first place.
    _fireProfTimer ??=
        Timer.periodic(const Duration(seconds: 10), (_) => _firehoseProfileFetch());
    return subId;
  }

  Timer? _fireWatchdog;
  int _fireLastEventMs = 0;
  int _fireSilentRounds = 0;
  static const int _fireSilenceMs = 60 * 1000;

  // Authors whose posts are held pending a profile. Fetched in ONE small REQ on
  // a slow timer — see the note in the FeedPending branch for why this is not
  // trackProfile.
  final Set<String> _profileWanted = {};
  final Map<String, int> _fireProfSubs = {}; // one-shot REQ subs → created ms
  Timer? _fireProfTimer;
  static const int _fireProfBatch = 100;
  static const int _fireProfTtlMs = 30 * 1000;

  void _firehoseProfileFetch() {
    // Reap the one-shot REQs: their answers arrived long ago, or are not coming,
    // and an open filter taxes every future event the relay sends us.
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    for (final sub in [
      for (final e in _fireProfSubs.entries)
        if (nowMs - e.value > _fireProfTtlMs) e.key,
    ]) {
      _fireProfSubs.remove(sub);
      _subFilters.remove(sub);
      _inbox.remove(sub);
      _seen.remove(sub);
      for (final c in _clients.values) {
        c.unsubscribe(sub);
      }
    }

    if (_profileWanted.isEmpty) return;
    final batch = <String>[];
    for (final p in _profileWanted) {
      if (_haveProfile.contains(p)) continue;
      batch.add(p);
      if (batch.length >= _fireProfBatch) break;
    }
    _profileWanted.removeAll(batch);
    if (batch.isEmpty) return;

    final sub = 'fireP${_subSeq++}';
    final f = [NostrFilter(kinds: const [0], authors: batch)];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    _fireProfSubs[sub] = nowMs;
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  void _openFirehoseReq() {
    final sub = 'fireR${_subSeq++}';
    _fireSub = sub;
    _fireLastEventMs = DateTime.now().millisecondsSinceEpoch;
    // kind-0 rides along with kind-1 on purpose — see above.
    final f = [const NostrFilter(kinds: [0, 1], limit: 200)];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  void _closeFirehoseReq() {
    final sub = _fireSub;
    _fireSub = null;
    if (sub == null) return;
    _subFilters.remove(sub);
    _inbox.remove(sub);
    _seen.remove(sub);
    for (final c in _clients.values) {
      c.unsubscribe(sub);
    }
  }

  void _teardownFirehose() {
    _fireWatchdog?.cancel();
    _fireWatchdog = null;
    _fireProfTimer?.cancel();
    _fireProfTimer = null;
    _profileWanted.clear();
    _fireFilter = null;
    _closeFirehoseReq();
  }

  bool _hasProfile(String pub) {
    if (_haveProfile.contains(pub)) return true;
    if (_noProfile.contains(pub)) return false;
    final known = profileOf(pub) != null;
    (known ? _haveProfile : _noProfile).add(pub);
    // Bound the miss set: a firehose meets an endless supply of strangers.
    if (_noProfile.length > 20000) _noProfile.clear();
    return known;
  }

  /// One firehose event. Returns true if it was handled here (so [_onEvent]
  /// stops), false to fall through to the normal path.
  /// Events that actually reached the firehose. Without this, an empty feed is
  /// ambiguous: is the gate eating everything, or is the relay sending nothing?
  /// Those have completely different fixes, and guessing wastes a build cycle.
  int fireSeen = 0;

  bool _onFirehose(NostrEvent event, int nowMs) {
    fireSeen++;
    _fireLastEventMs = nowMs; // the watchdog's proof of life
    _fireSilentRounds = 0;
    final filter = _fireFilter;
    if (filter == null) return true;

    // A profile: remember it, keep it (the UI needs the name and picture), and
    // release whatever of that author's posts was waiting on exactly this.
    if (event.kind == NostrEventKind.setMetadata) {
      _haveProfile.add(event.pubkey);
      _noProfile.remove(event.pubkey);
      if (store.put(event)) eventsStored++;
      for (final held in filter.release(event.pubkey, nowMs)) {
        _deliverFirehose(held);
      }
      return true;
    }

    if (event.kind != NostrEventKind.textNote) return true;

    final verdict = filter.verdict(
      event,
      hasProfile: _hasProfile,
      trusted: trustedAuthors.contains,
      muted: _isMuted,
      nowMs: nowMs,
    );
    switch (verdict) {
      case FeedKeep():
        // Store only what we would show. Persisting the whole public firehose
        // would be an INSERT per junk post on the engine isolate, forever.
        if (store.put(event)) {
          eventsStored++;
          onStored?.call(event);
        }
        _deliverFirehose(event);
      case FeedPending():
        // Hold it, and QUEUE the author for a profile lookup.
        //
        // Deliberately NOT trackProfile(): that one re-issues a single REQ
        // carrying up to 500 authors every time it is called, and a firehose
        // introduces a new stranger every second or two. The resulting REQ storm
        // got our subscriptions dropped by the relays — including the firehose
        // itself, which then went silent while the profiles it was waiting for
        // never arrived. The feed strangled itself.
        //
        // [_profileWanted] instead accumulates authors and asks for them in one
        // small batch on a slow timer (see [_firehoseProfileFetch]).
        filter.hold(event, nowMs);
        if (_profileWanted.length < 2000) _profileWanted.add(event.pubkey);
      case FeedReject():
        break; // counted in the filter's stats; never stored, never shown
    }
    return true;
  }

  void _deliverFirehose(NostrEvent event) {
    for (final id in _fireSubscribers) {
      _bufferForSub(id, event);
    }
  }

  /// Firehose accounting — what arrived, what was kept/held, and a count per
  /// drop reason. "The feed looks empty" must be answerable from the log.
  Map<String, int> drainFirehoseStats() {
    final f = _fireFilter;
    if (f == null) return const {};
    final seen = fireSeen;
    fireSeen = 0;
    return {'seen': seen, ...f.drainStats()};
  }

  // Live discoF fetch subs → created-at ms. These are one-shot id fetches; the
  // relays answer within seconds. They used to be created every 3s and NEVER
  // unsubscribed — after hours the filter set grew unbounded and every inbound
  // event paid an O(subs) match against it (a measured hot engine isolate).
  final Map<String, int> _discoFetchSubs = {};
  static const int _discoFetchTtlMs = 30 * 1000;

  // The first fetch of a cold discovery feed.
  //
  // Discovery is two steps: tally kind-7 reactions, then REQ the posts that
  // qualified. The tally is empty when the feed is first subscribed, so the
  // fetch at subscribe time has nothing to ask for — and the next one is the
  // 10-minute poll. That left a fresh install staring at an empty hero for ten
  // minutes, which is precisely when it most needs something to show.
  //
  // So: once the reactions start qualifying posts, fetch them shortly after,
  // ONCE. The debounce lets a burst of reactions accumulate into a single REQ
  // rather than one per post, and after this the slow poll takes over — this is
  // not a return to the 3-second polling that used to peg the engine.
  Timer? _discoPrime;
  bool _discoPrimed = false;

  void _primeDiscovery() {
    if (_discoPrimed || _discoPrime != null) return;
    _discoPrime = Timer(const Duration(seconds: 5), () {
      _discoPrime = null;
      _discoPrimed = true;
      _discoFetch();
    });
  }

  void _discoFetch() {
    // Reap fetch subs past their TTL — their ids either arrived long ago or
    // aren't coming; keeping the filter only taxes every future event.
    if (_discoFetchSubs.isNotEmpty) {
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      final expired = [
        for (final e in _discoFetchSubs.entries)
          if (nowMs - e.value > _discoFetchTtlMs) e.key,
      ];
      for (final sub in expired) {
        _discoFetchSubs.remove(sub);
        unsubscribe(sub);
      }
    }
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
    _discoFetchSubs[sub] = DateTime.now().millisecondsSinceEpoch;
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
      _primeDiscovery();
      // Seed the on-screen like tally with the reactions that qualified this
      // post, so it shows its real count (>=2) immediately instead of 0.
      _statReact.putIfAbsent(liked, () => <String>{}).addAll(likers);
      if (!_statTracked.contains(liked)) {
        _statTracked.add(liked);
        _statReply.putIfAbsent(liked, () => <String>{});
      }
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
  // NIP-25 says the reaction's CONTENT carries the verdict: "-" is a downvote,
  // anything else ("+", "🤙", an emoji) is a like. Tallying only "did someone
  // react" cannot tell an upvote from a downvote, so keep the two apart.
  final Map<String, Set<String>> _statUp = {};   // eventId → upvoter pubkeys
  final Map<String, Set<String>> _statDown = {}; // eventId → downvoter pubkeys
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
      // Seed from the store so counts are correct IMMEDIATELY (persisted
      // reaction receipts + already-stored kind-1 replies) instead of zero
      // until the relays redeliver. Live events then dedup into these sets.
      _statReact[id] = store.reactionPubkeys(id).toSet();
      _statReply[id] = store.replyIdsFor(id).toSet();
      _statUp[id] = <String>{};
      _statDown[id] = <String>{};
      added = true;
    }
    while (_statTracked.length > 300) {
      final old = _statTracked.removeAt(0);
      _statReact.remove(old);
      _statReply.remove(old);
      _statUp.remove(old);
      _statDown.remove(old);
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
      // NIP-25 puts the verdict in the content. Three DISJOINT buckets, so a
      // post is not counted twice: "+"/👍 is an upvote, "-"/👎 a downvote, and
      // any other emoji ("❤️", "🤙") is a plain like. Lumping them together
      // lit the heart and the thumb for the same single reaction.
      final c = event.content.trim();
      final isUp = c == '+' || c == '👍';
      final isDown = c == '-' || c == '👎';
      if (isUp) {
        _statUp[ref]?.add(event.pubkey);
        _statDown[ref]?.remove(event.pubkey);
        _statReact[ref]?.remove(event.pubkey);
      } else if (isDown) {
        _statDown[ref]?.add(event.pubkey);
        _statUp[ref]?.remove(event.pubkey);
        _statReact[ref]?.remove(event.pubkey);
      } else {
        _statReact[ref]?.add(event.pubkey);
      }
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

  /// (upvotes, downvotes, myVote) for a post id. myVote is 1, -1 or 0.
  (int, int, int) votesOf(String id, String? selfPub) {
    final up = _statUp[id];
    final down = _statDown[id];
    var mine = 0;
    if (selfPub != null) {
      if (up?.contains(selfPub) ?? false) {
        mine = 1;
      } else if (down?.contains(selfPub) ?? false) {
        mine = -1;
      }
    }
    return (up?.length ?? 0, down?.length ?? 0, mine);
  }

  /// Our own vote, recorded before it round-trips back from a relay.
  void recordVote(String id, String pub, int vote) {
    _statUp.putIfAbsent(id, () => <String>{});
    _statDown.putIfAbsent(id, () => <String>{});
    _statReact[id]?.remove(pub); // a vote is not also a like
    if (vote > 0) {
      _statUp[id]!.add(pub);
      _statDown[id]!.remove(pub);
    } else if (vote < 0) {
      _statDown[id]!.add(pub);
      _statUp[id]!.remove(pub);
    } else {
      _statUp[id]!.remove(pub);
      _statDown[id]!.remove(pub);
    }
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

  bool _profDirty = false;

  /// Ensure we subscribe to (and thus store) the kind-0 profile for [pub]. Safe
  /// to call repeatedly; a rolling window keeps the REQ bounded.
  ///
  /// The timer here is a BATCH WINDOW, not a debounce, and the difference is the
  /// whole feature. It used to `cancel()` the pending timer on every new author
  /// — fine when authors trickled in from a feed you follow, fatal under a
  /// firehose: a new stranger every few hundred milliseconds reset the timer
  /// forever, so the profile REQ was never actually sent, and every post from a
  /// stranger sat waiting for a profile nobody had asked for. Let the first
  /// timer run; the authors that arrive meanwhile ride along in the same batch.
  void trackProfile(String pub) {
    if (pub.length != 64 || !_profSeen.add(pub)) return;
    _profTracked.add(pub);
    while (_profTracked.length > 500) {
      _profSeen.remove(_profTracked.removeAt(0));
    }
    _profDirty = true;
    if (_profDebounce != null) return; // a batch is already in flight
    _profDebounce = Timer(const Duration(seconds: 2), () {
      _profDebounce = null;
      if (!_profDirty) return;
      _profDirty = false;
      _profResub();
    });
  }

  void _profResub() {
    if (_profTracked.isEmpty) return;
    // Re-subscribe kind-0 for ALL tracked authors. The persistent store already
    // avoids cross-session re-download (profileOf reads it); re-subscribing here
    // keeps retrying authors whose kind-0 hasn't arrived yet, which matters for
    // name coverage under a busy feed. Prioritise authors we DON'T yet have so a
    // huge author list can't starve the un-resolved ones.
    final have = <String>[];
    final missing = <String>[];
    for (final p in _profTracked) {
      (profileOf(p) == null ? missing : have).add(p);
    }
    final authors = [...missing, ...have];
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
    final f = [NostrFilter(kinds: const [0], authors: authors)];
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
  /// Sqlite profile lookups performed — counted because an unbounded re-query
  /// of absent profiles once pegged an entire core with nothing to show for it.
  int profileLookups = 0;

  /// One event by id, from the store (it is there once any relay delivered it).
  NostrEvent? eventById(String id) {
    if (id.length != 64) return null;
    final evs = store.query(NostrFilter(ids: [id], limit: 1));
    return evs.isEmpty ? null : evs.first;
  }

  /// Ask the relays for an event we do not hold yet (a notification about a
  /// post this device never saw in its own feed, say).
  void fetchEvent(String id) {
    if (id.length != 64) return;
    final sub = 'ev${_subSeq++}';
    final f = [NostrFilter(ids: [id], limit: 1)];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  /// Everything anyone has done to MY posts — reactions, replies, reposts and
  /// mentions — newest first, READ FROM THE LOCAL STORE.
  ///
  /// This is the whole point of keeping them at tier `self`: the notification
  /// list is answerable with the relays unreachable and after a restart, which
  /// an in-memory list drained from a live subscription never was.
  List<NostrEvent> myNotifications({int limit = 100}) {
    final me = selfPubkey;
    if (me == null) return const [];
    final evs = store.query(NostrFilter(
      kinds: const [1, 6, 7],
      tags: {'p': [me]},
      limit: limit,
    ));
    final out = [for (final e in evs) if (e.pubkey != me) e];
    out.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    return out;
  }

  NostrEvent? profileOf(String pub) {
    profileLookups++;
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

  /// Inbound-event accounting. The relay firehose is the engine isolate's whole
  /// workload, so these are what attribute (and bound) its CPU.
  int eventsSeen = 0;
  int eventsStored = 0;
  int reactionsStored = 0;

  Map<String, int> drainEventStats() {
    final out = {
      'seen': eventsSeen,
      'stored': eventsStored,
      'reactions': reactionsStored,
      'dropped': rateDropped,
      'profileLookups': profileLookups,
    };
    eventsSeen = 0;
    eventsStored = 0;
    reactionsStored = 0;
    rateDropped = 0;
    profileLookups = 0;
    return out;
  }

  /// Is this event mine — my post, or someone's reaction/reply/repost OF my
  /// post (it p-tags me)?
  bool _isMine(NostrEvent event) {
    final me = selfPubkey;
    if (me == null) return false;
    if (event.pubkey == me) return true;
    for (final t in event.tags) {
      if (t.length >= 2 && t[0] == 'p' && t[1] == me) return true;
    }
    return false;
  }

  void _onEvent(String subId, NostrEvent event) {
    eventsSeen++;

    // MY OWN CORNER OF THE NETWORK IS NOT CACHE.
    //
    // A reaction to my post is a fact about me, and this is an off-grid app:
    // the relay that delivered it may be unreachable for days. It is stored
    // here, at tier `self`, BEFORE the reaction short-circuit and BEFORE the
    // firehose rate cap — both of which used to drop it on the floor, so the
    // notification list survived only as long as the process did, and opening
    // the post it was about went back to the network for something we had
    // already been given.
    if (_isMine(event)) {
      if (store.put(event, tier: 0)) {
        eventsStored++;
        onStored?.call(event);
      }
      final ref = _firstETag(event);
      if (event.kind == NostrEventKind.reaction && ref != null) {
        store.addReaction(ref, event.pubkey);
      }
    }
    // Persist reaction receipts (post id + reactor) so like totals survive a
    // restart instead of crawling back over the network.
    //
    // ONLY for posts we actually track. The discovery subscription is a kind-7
    // firehose across every public relay, and persisting all of it meant one
    // unbatched sqlite INSERT per inbound reaction — thousands a minute, ahead
    // of the rate cap, burning the engine isolate for rows no one would ever
    // read. Tracked posts are exactly the ones the UI displays (trackStats
    // registers them, and seeds their tallies back from these rows), so this is
    // the whole set the persistence was ever for.
    if (event.kind == NostrEventKind.reaction) {
      final liked = _firstETag(event);
      if (liked != null && _statReact.containsKey(liked)) {
        if (store.addReaction(liked, event.pubkey)) reactionsStored++;
      }
    }
    // Engagement (likes/replies) is tallied for on-screen posts BEFORE the rate
    // cap so counts stay accurate. Reactions are tally-only (never displayed).
    final wasReaction = _tallyStats(event);
    // Reactions also drive the discovery tally; both consume the reaction here.
    if (_discoTally(event)) return;
    if (wasReaction) return;

    final now = DateTime.now().millisecondsSinceEpoch;

    // The firehose has its own rules: the QUALITY GATE decides whether this is
    // stored and shown at all, so it never reaches the generic path below.
    //
    // It runs BEFORE the rate cap, and that ordering is the whole point. The cap
    // used to come first and it ate the All feed alive: relays answer a fresh
    // kind-1 subscription with a burst (200 events each, times every relay), the
    // cap is 15 per 250ms, so the burst was discarded WITHOUT the gate ever
    // seeing it — `dropped=173, fireSeen=0, stored=0` while four relays were
    // happily streaming. The cap exists to protect the STORE from a firehose of
    // junk, and the gate already does that job better: it stores only what it
    // would show. Everything it rejects costs one cheap in-memory verdict.
    if (subId == _fireSub) {
      _onFirehose(event, now);
      return;
    }

    // The generic path stores EVERYTHING it is handed, so it keeps the cap.
    if (now - _rateWindowStart >= _rateWindowMs) {
      _rateWindowStart = now;
      _rateCount = 0;
    }
    if (_rateCount >= _rateMaxPerWindow) {
      rateDropped++; // overflow — dropped before it can reach sqlite
      return;
    }
    _rateCount++;

    // Merge into the unified store (dedup + replaceable/deletion handled there).
    if (store.put(event)) {
      eventsStored++;
      onStored?.call(event);
    }

    // A profile — from ANY subscription, not just the firehose. The kind-0 we
    // are waiting on usually arrives on the profile-tracking subscription
    // (trackProfile), so the release has to live here or the held posts would
    // sit there while their author's profile sat in the store.
    if (event.kind == NostrEventKind.setMetadata) {
      _haveProfile.add(event.pubkey);
      _noProfile.remove(event.pubkey);
      final filter = _fireFilter;
      if (filter != null) {
        for (final held in filter.release(event.pubkey, now)) {
          _deliverFirehose(held);
        }
      }
    }

    // A liked-enough post (fetched by id) goes to EVERY discovery subscriber.
    if (_discoSubscribers.isNotEmpty &&
        event.kind == NostrEventKind.textNote &&
        event.id != null &&
        _discoWanted.contains(event.id)) {
      for (final id in _discoSubscribers) {
        _bufferForSub(id, event);
      }
    }
    _bufferForSub(subId, event);
    // Bound the seen-set by EVICTING the oldest, never by emptying it. Clearing
    // it wholesale meant the next thing a relay re-sent (and relays re-send
    // their recent window on every re-open) looked new again — the same post,
    // buffered a second time, shown twice in the feed.
    final seen = _seen[subId];
    if (seen != null) {
      while (seen.length > _maxInbox * 4) {
        seen.remove(seen.first);
      }
    }
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
    _fireWatchdog?.cancel();
    _fireWatchdog = null;
    _fireProfTimer?.cancel();
    _fireProfTimer = null;
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
