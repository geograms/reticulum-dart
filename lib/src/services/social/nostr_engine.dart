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
import 'dart:isolate';

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
  const _EngineInit(
      this.toMain, this.storePath, this.persistPath, this.selfPubHex);
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
  final Map<String, List<Map<String, dynamic>>> _subEvents = {}; // subId → queue
  final Map<String, (int, int, bool)> _stats = {}; // eventId → (likes,replies,mine)
  final Set<String> _likedLocally = {}; // ids we've liked (keep them filled)
  final Map<String, Map<String, String>> _profiles = {}; // pub → profile
  final Map<String, Map<String, String>> _profByShort12 = {}; // pub[:12] → profile
  final Map<String, List<Map<String, dynamic>>> _replies = {}; // postId → replies
  static const int _subQueueMax = 800;

  /// Optional: notified (throttled) when caches change, so the UI can repaint.
  void Function()? onChanged;

  static Future<NostrClient> spawn({
    required String storePath,
    String? persistPath,
    String? selfPubHex,
  }) async {
    final c = NostrClient._();
    c._fromEngine.listen(c._onFromEngine);
    c._iso = await Isolate.spawn(
      _engineMain,
      _EngineInit(c._fromEngine.sendPort, storePath, persistPath, selfPubHex),
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
    switch (msg['snap']) {
      case 'relays':
        _relays = (msg['json'] as List).cast<Map<String, dynamic>>();
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
        });
      case 'profiles':
        (msg['entries'] as Map).forEach((k, v) {
          final m = (v as Map).cast<String, String>();
          _profiles['$k'] = m;
          if ('$k'.length >= 12) _profByShort12['$k'.substring(0, 12)] = m;
        });
      case 'replies':
        _replies['${msg['id']}'] =
            (msg['events'] as List).cast<Map<String, dynamic>>();
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

  String subscribeDiscovery({int minLikes = 3}) {
    final subId = 'd${_subSeq++}';
    _subEvents[subId] = [];
    _send({'cmd': 'discovery', 'subId': subId, 'minLikes': minLikes});
    return subId;
  }

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

  void recordReaction(String id, String pub) {
    // Optimistic local bump so the heart fills before it round-trips.
    _likedLocally.add(id);
    final cur = _stats[id] ?? (0, 0, false);
    if (!cur.$3) _stats[id] = (cur.$1 + 1, cur.$2, true);
    _send({'cmd': 'recordReaction', 'id': id, 'pub': pub});
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
    // All store/relay setup runs on THIS (background) isolate.
    final engine = _Engine(
        init.toMain, init.storePath, init.persistPath, init.selfPubHex);
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
  final Map<String, (int, int, bool)> _statsSent = {};
  final Set<String> _profSent = {};
  Timer? _timer;
  bool _ok = false;

  _Engine(this.toMain, String storePath, String? persistPath, this.selfPub) {
    try {
      _store = RelayEventStore.open(storePath);
      _hub = NostrRelayHub(
        store: NostrStore.of(_store),
        persistPath: persistPath,
        rnsClientFactory: null, // RNS lives on the main isolate; wss + local here
      );
      // ignore: discarded_futures
      _hub.init();
      _ok = true;
      _sendStoredProfiles(); // hydrate the UI's profile index from disk
      _timer = Timer.periodic(const Duration(milliseconds: 400), (_) => _tick());
    } catch (_) {
      _ok = false;
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
              minLikes: (c['minLikes'] as int?) ?? 3);
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

  void _tick() {
    // Relay statuses.
    toMain.send({'snap': 'relays', 'json': _hub.relaysJson()});

    // Drained events per wapp-facing sub.
    for (final sub in _drainSubs) {
      final evs = _hub.drainEvents(sub, max: 60);
      if (evs.isNotEmpty) {
        toMain.send({'snap': 'events', 'subId': sub, 'events': evs});
      }
    }

    // Changed engagement stats.
    final statEntries = <String, List<Object>>{};
    for (final id in _hub.trackedStatIds) {
      final s = _hub.statsOf(id, selfPub);
      final prev = _statsSent[id];
      if (prev == null || prev != s) {
        _statsSent[id] = s;
        statEntries[id] = [s.$1, s.$2, s.$3];
      }
    }
    if (statEntries.isNotEmpty) {
      toMain.send({'snap': 'stats', 'entries': statEntries});
    }

    // New profiles.
    final profEntries = <String, Map<String, String>>{};
    for (final pub in _hub.trackedProfilePubs) {
      if (_profSent.contains(pub)) continue;
      final p = _profileMap(pub);
      if (p.isNotEmpty && p['name'] != null) {
        _profSent.add(pub);
        profEntries[pub] = p;
      }
    }
    if (profEntries.isNotEmpty) {
      toMain.send({'snap': 'profiles', 'entries': profEntries});
    }
  }

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
