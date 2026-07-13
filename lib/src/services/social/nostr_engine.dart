/*
 * NostrEngine — runs the ENTIRE NOSTR relay pipeline on a dedicated background
 * isolate, so the UI isolate never touches it.
 *
 * The UI isolate saturating on a public firehose (hundreds of frames/s × N
 * relays) was the root of the "app not responding" reports: WebSocket receive,
 * JSON decode, BIP-340 verify, SQLite writes, and the like/reply/profile tallies
 * all ran on the main isolate. Here every one of those runs inside the engine
 * isolate. The main side ([NostrClient]) only:
 *   - sends fire-and-forget COMMANDS (subscribe, publish, track, …), and
 *   - reads lazily-updated CACHES that the engine refreshes on a timer.
 * Nothing on the UI isolate ever blocks on relay work.
 *
 * Messages are plain sendable maps/lists (no shared objects). Events cross the
 * boundary as their NIP-01 JSON, which is exactly what the wapp consumes anyway.
 */
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';

import 'package:sqlite3/open.dart' as sqlite_open;

import '../../util/nostr_crypto.dart';
import '../../util/nostr_event.dart';
import 'nostr_relay_hub.dart';
import 'relay_event_store.dart';

/// Init payload handed to the freshly-spawned engine isolate.
class _EngineInit {
  final SendPort toMain;
  final String storePath;
  final String? persistPath;
  final String? selfPubHex;

  /// Native SQLite library to load ON THIS ISOLATE, e.g. 'libsqlcipher.so'.
  ///
  /// package:sqlite3's loader override is PER-ISOLATE. A host that bundles
  /// SQLCipher instead of stock SQLite (aurora does, for encrypted profiles)
  /// sets its override on the main isolate — and the engine isolate then
  /// tries to load a libsqlite3.so that is not in the app at all, throws, and
  /// the whole NOSTR pipeline silently never starts.
  final String? sqliteLibrary;

  /// SQLCipher key (raw hex) for [storePath]. Null = plain database.
  final String? dbKeyHex;

  const _EngineInit(
    this.toMain,
    this.storePath,
    this.persistPath,
    this.selfPubHex, {
    this.sqliteLibrary,
    this.dbKeyHex,
  });
}

/// Main-isolate proxy: mints subscription ids, forwards commands to the engine,
/// and serves the wapp from caches the engine refreshes. Every method here is
/// cheap (a map lookup or a port send) — no relay/SQLite work on this isolate.
class NostrClient {
  NostrClient._();

  Isolate? _iso;
  SendPort? _toEngine;
  final ReceivePort _fromEngine = ReceivePort();
  bool _ready = false;
  final List<Map<String, dynamic>> _preReady = []; // commands queued pre-handshake

  int _subSeq = 0;

  // ── Caches (refreshed by engine snapshots) ─────────────────────────────────
  List<Map<String, dynamic>> _relays = const [];

  /// Inbound-event rates from the engine isolate (seen/stored/reactions/
  /// dropped per push window). The relay firehose IS this isolate's workload,
  /// so this is how the host attributes its CPU. Reset each engine push.
  Map<String, int> _eventStats = const {};
  Map<String, int> get eventStats => _eventStats;
  final Map<String, List<Map<String, dynamic>>> _subEvents = {}; // subId → queue
  final Map<String, (int, int, bool)> _stats = {}; // eventId → (likes,replies,mine)
  // eventId → (upvotes, downvotes, myVote ∈ {-1,0,1}). NIP-25 puts the verdict
  // in the reaction's content: "-" is a downvote, anything else is a like.
  final Map<String, (int, int, int)> _votes = {};

  /// Single events fetched by id (see [eventById]).
  final Map<String, Map<String, dynamic>> _events = {};
  final Set<String> _likedLocally = {}; // ids we've liked (keep them filled)
  final Map<String, Map<String, String>> _profiles = {}; // pub → profile
  final Map<String, Map<String, String>> _profByShort12 = {}; // pub[:12] → profile
  final Map<String, List<Map<String, dynamic>>> _replies = {}; // postId → replies
  List<String> _myFollows = const []; // my kind-3 contact list (hex pubkeys)
  static const int _subQueueMax = 800;

  /// Optional: notified (throttled) when caches change, so the UI can repaint.
  void Function()? onChanged;

  /// Engine-side log lines (e.g. a store that refused to open). The host
  /// pipes these into its own log so a dead pipeline is never silent.
  ///
  /// Setting it flushes whatever the engine already said: the isolate reports
  /// a failed store open in its constructor, which is BEFORE spawn() has even
  /// returned to the host — those lines used to fall on the floor, which is
  /// how a completely dead NOSTR pipeline stayed invisible.
  void Function(String msg)? get onLog => _onLog;
  set onLog(void Function(String msg)? f) {
    _onLog = f;
    if (f == null) return;
    for (final l in _logBuffer) {
      f(l);
    }
    _logBuffer.clear();
  }

  void Function(String msg)? _onLog;
  final List<String> _logBuffer = [];

  static Future<NostrClient> spawn({
    required String storePath,
    String? persistPath,
    String? selfPubHex,
    String? sqliteLibrary,
    String? dbKeyHex,
  }) async {
    final c = NostrClient._();
    c._fromEngine.listen(c._onFromEngine);
    c._iso = await Isolate.spawn(
      _engineMain,
      _EngineInit(
        c._fromEngine.sendPort,
        storePath,
        persistPath,
        selfPubHex,
        sqliteLibrary: sqliteLibrary,
        dbKeyHex: dbKeyHex,
      ),
      debugName: 'nostr-engine',
    );
    return c;
  }

  void _send(Map<String, dynamic> cmd) {
    final p = _toEngine;
    if (p == null) {
      _preReady.add(cmd);
    } else {
      p.send(cmd);
    }
  }

  void _onFromEngine(dynamic msg) {
    if (msg is SendPort) {
      _toEngine = msg;
      _ready = true;
      for (final c in _preReady) {
        msg.send(c);
      }
      _preReady.clear();
      return;
    }
    if (msg is! Map) return;
    final line = msg['log'];
    if (line is String) {
      final sink = _onLog;
      if (sink != null) {
        sink(line);
      } else if (_logBuffer.length < 100) {
        _logBuffer.add(line);
      }
      return;
    }
    switch (msg['snap']) {
      case 'relays':
        _relays = (msg['json'] as List).cast<Map<String, dynamic>>();
      case 'evstats':
        _eventStats = (msg['stats'] as Map).cast<String, int>();
      case 'fhstats':
        firehoseStats = (msg['stats'] as Map).cast<String, int>();
      case 'events':
        final sub = msg['subId'] as String;
        final q = _subEvents.putIfAbsent(sub, () => []);
        q.addAll((msg['events'] as List).cast<Map<String, dynamic>>());
        if (q.length > _subQueueMax) {
          q.removeRange(0, q.length - _subQueueMax);
        }
      case 'stats':
        (msg['entries'] as Map).forEach((k, v) {
          final l = (v as List);
          var likes = l[0] as int;
          var mine = l[2] as bool;
          if (_likedLocally.contains('$k')) {
            mine = true; // keep our own like filled until the engine confirms
            if (likes < 1) likes = 1;
          }
          _stats['$k'] = (likes, l[1] as int, mine);
          if (l.length >= 6) {
            var up = l[3] as int;
            var down = l[4] as int;
            var my = l[5] as int;
            final local = _votedLocally['$k'];
            if (local != null) {
              my = local; // hold our own vote until the engine confirms it
              if (local > 0 && up < 1) up = 1;
              if (local < 0 && down < 1) down = 1;
            }
            _votes['$k'] = (up, down, my);
          }
        });
      case 'profiles':
        (msg['entries'] as Map).forEach((k, v) {
          final m = (v as Map).cast<String, String>();
          _profiles['$k'] = m;
          if ('$k'.length >= 12) _profByShort12['$k'.substring(0, 12)] = m;
        });
      case 'event':
        _events['${msg['id']}'] =
            (msg['event'] as Map).cast<String, dynamic>();
      case 'replies':
        _replies['${msg['id']}'] =
            (msg['events'] as List).cast<Map<String, dynamic>>();
      case 'myFollows':
        _myFollows = (msg['pubs'] as List).cast<String>();
    }
    onChanged?.call();
  }

  bool get ready => _ready;

  // ── Relay list ──────────────────────────────────────────────────────────
  List<Map<String, dynamic>> relaysJson() => _relays;

  bool addRelay(String uri) {
    final u = uri.trim();
    if (u.isEmpty) return false;
    if (_relays.any((r) => r['uri'] == u)) return false;
    _send({'cmd': 'addRelay', 'uri': u});
    // Optimistic: show it immediately as connecting.
    _relays = [
      ..._relays,
      {'uri': u, 'scheme': _schemeOf(u), 'enabled': true, 'status': 'connecting'}
    ];
    return true;
  }

  bool removeRelay(String uri) {
    if (!_relays.any((r) => r['uri'] == uri)) return false;
    _send({'cmd': 'removeRelay', 'uri': uri});
    _relays = _relays.where((r) => r['uri'] != uri).toList();
    return true;
  }

  static String _schemeOf(String u) => u.startsWith('wss://') || u.startsWith('ws://')
      ? 'websocket'
      : (u.startsWith('rns://') ? 'reticulum' : (u == 'local' ? 'local' : 'unknown'));

  // ── Subscriptions ─────────────────────────────────────────────────────────
  String subscribe(List<NostrFilter> filters) {
    final subId = 's${_subSeq++}';
    _subEvents[subId] = [];
    _send({
      'cmd': 'subscribe',
      'subId': subId,
      'filters': [for (final f in filters) f.toJson()],
    });
    return subId;
  }

  String subscribeDiscovery({int minLikes = 2}) {
    final subId = 'd${_subSeq++}';
    _subEvents[subId] = [];
    _send({'cmd': 'discovery', 'subId': subId, 'minLikes': minLikes});
    return subId;
  }

  /// The live firehose: kind-1 as the relays push it, passed through the quality
  /// gate. This is what an "All" feed is supposed to be — discovery (above) can
  /// only surface posts that already collected likes, so it is a *popular* feed
  /// and can never be a fresh one.
  String subscribeFirehose({bool requireProfile = true}) {
    final subId = 'f${_subSeq++}';
    _subEvents[subId] = [];
    _send({
      'cmd': 'firehose',
      'subId': subId,
      'requireProfile': requireProfile,
    });
    return subId;
  }

  /// Self + follows: they bypass the firehose gate. Push this whenever the
  /// follow set changes.
  void setTrustedAuthors(Iterable<String> pubs) =>
      _send({'cmd': 'trusted', 'pubs': pubs.toList()});

  /// Authors the user muted — never shown, whatever they post.
  void setMutedAuthors(Iterable<String> pubs) =>
      _send({'cmd': 'muted', 'pubs': pubs.toList()});

  /// Firehose accounting: kept / pending / expired, plus a count per drop
  /// reason. Empty until the first firehose subscription exists.
  Map<String, int> firehoseStats = const {};

  void unsubscribe(String subId) {
    _subEvents.remove(subId);
    _send({'cmd': 'unsubscribe', 'subId': subId});
  }

  List<Map<String, dynamic>> drainEvents(String subId, {int max = 50}) {
    final q = _subEvents[subId];
    if (q == null || q.isEmpty) return const [];
    final n = q.length < max ? q.length : max;
    final out = q.sublist(0, n);
    q.removeRange(0, n);
    return out;
  }

  // ── Publish (main signs, engine sends) ──────────────────────────────────
  Future<void> publish(NostrEvent event) async =>
      _send({'cmd': 'publish', 'event': event.toJson()});

  // ── Engagement ────────────────────────────────────────────────────────────
  void trackStats(List<String> ids) {
    final wanted = ids.where((id) => id.length == 64).toList();
    if (wanted.isEmpty) return;
    _send({'cmd': 'trackStats', 'ids': wanted});
  }

  (int, int, bool) statsOf(String id, String? selfPub) =>
      _stats[id] ?? (0, 0, false);

  /// (upvotes, downvotes, myVote) for a post.
  (int, int, int) votesOf(String id) => _votes[id] ?? (0, 0, 0);

  final Map<String, int> _votedLocally = {};

  /// Our own vote: 1 up, -1 down, 0 retracted. Bumps the count locally so the
  /// thumb fills at once instead of after a relay round-trip.
  void recordVote(String id, String pub, int vote) {
    _votedLocally[id] = vote;
    final cur = _votes[id] ?? (0, 0, 0);
    var up = cur.$1, down = cur.$2;
    if (vote > 0) {
      if (cur.$3 <= 0) up += 1;
      if (cur.$3 < 0 && down > 0) down -= 1;
    } else if (vote < 0) {
      if (cur.$3 >= 0) down += 1;
      if (cur.$3 > 0 && up > 0) up -= 1;
    }
    _votes[id] = (up, down, vote);
    _send({'cmd': 'recordVote', 'id': id, 'pub': pub, 'vote': vote});
  }

  void recordReaction(String id, String pub) {
    // Optimistic local bump so the heart fills before it round-trips.
    _likedLocally.add(id);
    final cur = _stats[id] ?? (0, 0, false);
    if (!cur.$3) _stats[id] = (cur.$1 + 1, cur.$2, true);
    _send({'cmd': 'recordReaction', 'id': id, 'pub': pub});
  }

  /// One event by id. Returns it when we hold it; otherwise asks the engine
  /// (and the relays) for it and answers null — call again once it lands.
  Map<String, dynamic>? eventById(String id) {
    final have = _events[id];
    if (have != null) return have;
    _send({'cmd': 'fetchEvent', 'id': id});
    return null;
  }

  // ── Profiles ──────────────────────────────────────────────────────────────
  void trackProfile(String pub) {
    if (pub.length != 64) return;
    _send({'cmd': 'trackProfile', 'pub': pub});
  }

  /// Parsed profile map (name/pic/about/nip05/website/lud16/banner/npub) or {}.
  Map<String, String> profile(String pub) {
    trackProfile(pub); // ensure it's being fetched
    return _profiles[pub] ?? const {};
  }

  /// Resolve a profile by the 12-char pubkey prefix the UI uses as a post's
  /// `from`. Backed by the engine's PERSISTENT store (every kind-0 ever seen is
  /// broadcast to this index at startup), so authors resolve even when they're
  /// not in the current live feed (Saved tab, old threads). {} if unknown.
  Map<String, String> profileByShort12(String short12) =>
      _profByShort12[short12] ?? const {};

  /// My kind-3 contact list (hex pubkeys), fetched from the relays.
  List<String> myFollows() => _myFollows;

  // ── Replies ─────────────────────────────────────────────────────────────
  List<Map<String, dynamic>> replies(String postId) {
    _send({'cmd': 'fetchReplies', 'id': postId}); // refresh (lazy)
    return _replies[postId] ?? const [];
  }

  Future<void> close() async {
    _send({'cmd': 'close'});
    await Future<void>.delayed(const Duration(milliseconds: 50));
    _iso?.kill(priority: Isolate.immediate);
    _iso = null;
    _fromEngine.close();
  }

  // ══ engine isolate ════════════════════════════════════════════════════════
  static Future<void> _engineMain(_EngineInit init) async {
    // The sqlite3 loader override is per-isolate: re-apply the host's choice
    // of native library here, BEFORE anything opens a database.
    final lib = init.sqliteLibrary;
    if (lib != null && lib.isNotEmpty) {
      DynamicLibrary open() => DynamicLibrary.open(lib);
      for (final os in sqlite_open.OperatingSystem.values) {
        sqlite_open.open.overrideFor(os, open);
      }
    }
    // All store/relay setup runs on THIS (background) isolate.
    final engine = _Engine(
      init.toMain,
      init.storePath,
      init.persistPath,
      init.selfPubHex,
      dbKeyHex: init.dbKeyHex,
    );
    final rx = ReceivePort();
    init.toMain.send(rx.sendPort);
    rx.listen((dynamic m) {
      if (m is Map) engine.handle(m.cast<String, dynamic>());
    });
  }
}

/// The actual worker living on the background isolate.
class _Engine {
  final SendPort toMain;
  String? selfPub; // learned from the first reaction if unset at spawn
  late final RelayEventStore _store;
  late final NostrRelayHub _hub;
  final Set<String> _drainSubs = {}; // wapp-facing subs to push to main
  final Set<String> _wantEvents = {}; // ids asked for, not yet in the store
  final Map<String, (int, int, bool, int, int, int)> _statsSent = {};
  final Set<String> _profSent = {};
  bool _myFollowsSub = false; // subscribed my kind-3 yet
  Set<String>? _myFollowsSent; // last contact-list set sent to main
  Timer? _timer;
  bool _ok = false;

  _Engine(this.toMain, String storePath, String? persistPath, this.selfPub,
      {String? dbKeyHex}) {
    try {
      _store = RelayEventStore.open(storePath, keyHex: dbKeyHex);
      _hub = NostrRelayHub(
        store: NostrStore.of(_store),
        persistPath: persistPath,
        rnsClientFactory: null, // RNS lives on the main isolate; wss + local here
        // Relay connects, drops and refusals go to the host log. Without this
        // a feed that never fills is indistinguishable from a feed with
        // nothing in it.
        log: (m) => toMain.send({'log': m}),
        // Only a newly-stored contact list can change our follow set, so that
        // is the only thing that makes _syncMyFollows do its (expensive) work.
        onStored: (e) {
          if (e.kind == NostrEventKind.contacts && e.pubkey == selfPub) {
            _myFollowsDirty = true;
          }
        },
      );
      // ignore: discarded_futures
      _hub.init();
      _ok = true;
      _sendStoredProfiles(); // hydrate the UI's profile index from disk
      _timer = Timer.periodic(const Duration(milliseconds: 400), (_) => _tick());
    } catch (e) {
      // A dead engine used to be SILENT — no relay ever connected and the feed
      // was simply empty forever, with nothing in the log to say why. Say it.
      _ok = false;
      toMain.send({'log': 'NOSTR engine failed to start: $e'});
    }
  }

  /// Broadcast EVERY kind-0 profile already in the persistent store to the main
  /// isolate at startup, so authors resolve in every view (Saved, old threads,
  /// profile page) without being in the current live feed.
  void _sendStoredProfiles() {
    try {
      final evs = _store.query(const NostrFilter(kinds: [0], limit: 5000));
      final seen = <String>{};
      final entries = <String, Map<String, String>>{};
      for (final e in evs) {
        if (!seen.add(e.pubkey)) continue;
        final m = _profileMap(e.pubkey);
        if (m['name'] != null) {
          entries[e.pubkey] = m;
          _profSent.add(e.pubkey);
        }
        if (entries.length >= 4000) break;
      }
      if (entries.isNotEmpty) {
        toMain.send({'snap': 'profiles', 'entries': entries});
      }
    } catch (_) {}
  }

  void handle(Map<String, dynamic> c) {
    if (!_ok) return;
    try {
      switch (c['cmd']) {
        case 'addRelay':
          _hub.addRelay('${c['uri']}');
        case 'removeRelay':
          _hub.removeRelay('${c['uri']}');
        case 'subscribe':
          final subId = '${c['subId']}';
          _drainSubs.add(subId);
          _hub.subscribeWithId(subId, _filters(c['filters']));
        case 'discovery':
          final subId = '${c['subId']}';
          _drainSubs.add(subId);
          _hub.subscribeDiscoveryWithId(subId,
              minLikes: (c['minLikes'] as int?) ?? 2);
        case 'firehose':
          final subId = '${c['subId']}';
          _drainSubs.add(subId);
          _hub.subscribeFirehoseWithId(subId,
              requireProfile: c['requireProfile'] != false);
        case 'trusted':
          // Self + everyone we follow. They bypass the firehose quality gate —
          // you do not vet someone you chose to follow.
          _hub.trustedAuthors = {
            for (final p in (c['pubs'] as List)) '$p',
          };
        case 'muted':
          _hub.mutedAuthors = {
            for (final p in (c['pubs'] as List)) '$p',
          };
        case 'unsubscribe':
          _drainSubs.remove('${c['subId']}');
          _hub.unsubscribe('${c['subId']}');
        case 'publish':
          _hub.publish(NostrEvent.fromJson(
              (c['event'] as Map).cast<String, dynamic>()));
        case 'trackStats':
          _hub.trackStats((c['ids'] as List).cast<String>());
        case 'recordReaction':
          final pub = '${c['pub']}';
          selfPub ??= pub; // learn our pubkey so the mine-check works
          _hub.recordReaction('${c['id']}', pub);
        case 'recordVote':
          final pub = '${c['pub']}';
          selfPub ??= pub;
          _hub.recordVote('${c['id']}', pub, (c['vote'] as num).toInt());
        case 'fetchEvent':
          final id = '${c['id']}';
          final have = _hub.eventById(id);
          if (have != null) {
            toMain.send({'snap': 'event', 'id': id, 'event': have.toJson()});
          } else {
            _hub.fetchEvent(id); // ask the relays; it lands in the store
            _wantEvents.add(id);
          }
        case 'trackProfile':
          _hub.trackProfile('${c['pub']}');
        case 'fetchReplies':
          _sendReplies('${c['id']}');
        case 'close':
          _timer?.cancel();
      }
    } catch (_) {}
  }

  List<NostrFilter> _filters(dynamic raw) => [
        if (raw is List)
          for (final f in raw)
            if (f is Map) NostrFilter.fromJson(f.cast<String, dynamic>())
      ];

  /// The NOSTR way to know who I follow: subscribe my own kind-3 contact list
  /// from the relays, parse its p-tags, and push the pubkeys to the main isolate
  /// (so follows made on ANY client show up here, not just local follows).
  // Our own contact list changes when a new kind-3 arrives — which is rare and
  // which the hub tells us about. Recomputing it on every 400ms tick meant a
  // sqlite query plus a re-parse of every p-tag (a contact list routinely has
  // thousands) 2.5 times a second, forever: a whole pegged core, for a value
  // that had not changed. The dedup guard below only ever suppressed the port
  // message, never the work. Gate on the STORED EVENT instead, and only re-read
  // when the hub has stored something new.
  int _myFollowsAt = 0; // createdAt of the kind-3 we last parsed
  bool _myFollowsDirty = true; // a new event landed — re-read on next tick

  void _syncMyFollows() {
    final me = selfPub;
    if (me == null || me.length != 64) return;
    if (!_myFollowsSub) {
      _myFollowsSub = true;
      _hub.subscribeWithId(
          'myfollows', [NostrFilter(kinds: const [3], authors: [me])]);
    }
    if (!_myFollowsDirty) return; // nothing new since we last parsed
    _myFollowsDirty = false;

    NostrEvent? latest;
    for (final e in _store.query(NostrFilter(kinds: const [3], authors: [me]))) {
      if (latest == null || e.createdAt > latest.createdAt) latest = e;
    }
    if (latest == null) return;
    if (latest.createdAt <= _myFollowsAt) return; // same list as last time
    _myFollowsAt = latest.createdAt;

    final pubs = <String>{};
    for (final t in latest.tags) {
      if (t.length >= 2 && t[0] == 'p' && t[1].length == 64) {
        pubs.add(t[1].toLowerCase());
      }
    }
    if (pubs.isEmpty) return;
    if (_myFollowsSent != null &&
        _myFollowsSent!.length == pubs.length &&
        _myFollowsSent!.containsAll(pubs)) {
      return; // unchanged
    }
    _myFollowsSent = pubs;
    toMain.send({'snap': 'myFollows', 'pubs': pubs.toList()});
  }

  void _tick() {
    // Relay statuses.
    toMain.send({'snap': 'relays', 'json': _hub.relaysJson()});

    _syncMyFollows();

    // Drained events per wapp-facing sub.
    for (final sub in _drainSubs) {
      final evs = _hub.drainEvents(sub, max: 60);
      if (evs.isNotEmpty) {
        toMain.send({'snap': 'events', 'subId': sub, 'events': evs});
      }
    }

    // Events the main isolate asked for (a notification's post, say) that have
    // since arrived from a relay.
    if (_wantEvents.isNotEmpty) {
      for (final id in _wantEvents.toList()) {
        final e = _hub.eventById(id);
        if (e == null) continue;
        _wantEvents.remove(id);
        toMain.send({'snap': 'event', 'id': id, 'event': e.toJson()});
      }
    }

    // Inbound-event rates — the firehose is this isolate's whole CPU cost.
    final ev = _hub.drainEventStats();
    if (ev.values.any((v) => v > 0)) {
      toMain.send({'snap': 'evstats', 'stats': ev});
    }

    // What the quality gate kept, held and dropped, by reason. Without this,
    // "the All tab looks empty" is unanswerable except by guesswork.
    final fh = _hub.drainFirehoseStats();
    if (fh.values.any((v) => v > 0)) {
      toMain.send({'snap': 'fhstats', 'stats': fh});
    }

    // Changed engagement stats.
    final statEntries = <String, List<Object>>{};
    for (final id in _hub.trackedStatIds) {
      final s = _hub.statsOf(id, selfPub);
      final v = _hub.votesOf(id, selfPub);
      final prev = _statsSent[id];
      final now = (s.$1, s.$2, s.$3, v.$1, v.$2, v.$3);
      if (prev == null || prev != now) {
        _statsSent[id] = now;
        statEntries[id] = [s.$1, s.$2, s.$3, v.$1, v.$2, v.$3];
      }
    }
    if (statEntries.isNotEmpty) {
      toMain.send({'snap': 'stats', 'entries': statEntries});
    }

    // New profiles.
    //
    // A MISS must be remembered, not just a hit. _profSent only records pubkeys
    // whose kind-0 we found, so every author we've seen but whose profile never
    // arrives (most of a public firehose) was re-queried against sqlite on
    // EVERY 400ms tick, forever — hundreds of queries a second, no events, one
    // core pegged. Re-check a miss only occasionally: the profile can still
    // show up later, but it costs one query per pubkey per window, not 150.
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    final profEntries = <String, Map<String, String>>{};
    var looked = 0;
    for (final pub in _hub.trackedProfilePubs) {
      if (_profSent.contains(pub)) continue;
      final retryAt = _profMissAt[pub];
      if (retryAt != null && nowMs - retryAt < _profMissRetryMs) continue;
      // Bound the work of any single tick, so a big backlog is spread out
      // instead of stalling the engine in one go.
      if (looked >= _profLookupsPerTick) break;
      looked++;
      final p = _profileMap(pub);
      if (p.isNotEmpty && p['name'] != null) {
        _profSent.add(pub);
        _profMissAt.remove(pub);
        profEntries[pub] = p;
      } else {
        _profMissAt[pub] = nowMs;
      }
    }
    if (profEntries.isNotEmpty) {
      toMain.send({'snap': 'profiles', 'entries': profEntries});
    }
  }

  // pubkey -> when we last looked for its (absent) kind-0 profile.
  final Map<String, int> _profMissAt = {};
  static const int _profMissRetryMs = 5 * 60 * 1000;
  static const int _profLookupsPerTick = 8;

  void _sendReplies(String postId) {
    final out = [
      for (final e in _hub.repliesTo(postId))
        {
          'id': e.id ?? '',
          'pubkey': e.pubkey,
          'content': e.content,
          'ts': e.createdAt,
        }
    ];
    toMain.send({'snap': 'replies', 'id': postId, 'events': out});
  }

  Map<String, String> _profileMap(String pub) {
    final ev = _hub.profileOf(pub);
    final out = <String, String>{};
    try {
      out['npub'] = NostrCrypto.encodeNpub(pub);
    } catch (_) {}
    if (ev == null) return out;
    try {
      final j = jsonDecode(ev.content);
      if (j is Map) {
        String s(String k) => (j[k] ?? '').toString().trim();
        final name = s('display_name').isNotEmpty
            ? s('display_name')
            : (s('displayName').isNotEmpty ? s('displayName') : s('name'));
        if (name.isNotEmpty) out['name'] = name;
        if (s('picture').startsWith('http')) out['pic'] = s('picture');
        if (s('about').isNotEmpty) out['about'] = s('about');
        if (s('nip05').isNotEmpty) out['nip05'] = s('nip05');
        if (s('website').isNotEmpty) out['website'] = s('website');
        final lud = s('lud16').isNotEmpty ? s('lud16') : s('lud06');
        if (lud.isNotEmpty) out['lud16'] = lud;
        if (s('banner').startsWith('http')) out['banner'] = s('banner');
      }
    } catch (_) {}
    return out;
  }
}
