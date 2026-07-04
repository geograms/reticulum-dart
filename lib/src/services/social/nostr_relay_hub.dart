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
import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import '../../util/nostr_event.dart';
import 'nostr_local_client.dart';
import 'nostr_relay_client.dart';
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
  String subscribe(List<NostrFilter> filters) {
    final subId = 'h${_subSeq++}';
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

  void _onEvent(String subId, NostrEvent event) {
    // Merge into the unified store (dedup + replaceable/deletion handled there).
    if (store.put(event)) onStored?.call(event);
    final inbox = _inbox[subId];
    final seen = _seen[subId];
    if (inbox == null || seen == null || event.id == null) return;
    if (!seen.add(event.id!)) return; // already delivered on this sub
    inbox.add(event);
    while (inbox.length > _maxInbox) {
      inbox.removeFirst();
    }
    if (seen.length > _maxInbox * 4) seen.clear();
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

  /// Publish an event to the local store + every enabled relay.
  Future<void> publish(NostrEvent event) async {
    if (store.put(event, tier: 0)) onStored?.call(event);
    for (final e in _endpoints.values) {
      if (!e.enabled) continue;
      // ignore: discarded_futures
      _clients[e.uri]?.publish(event);
    }
  }

  Future<void> close() async {
    for (final c in _clients.values) {
      await c.close();
    }
    _clients.clear();
  }
}
