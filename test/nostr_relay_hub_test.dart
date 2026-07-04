/*
 * NostrRelayHub — the transport-abstract orchestrator: relay list add/remove/
 * persist, subscribe fanning to every transport, inbound events merging into the
 * ONE store and buffering per-sub for the wapp to drain, publish fanning out.
 * A fake client stands in for the network transports so no sockets are opened.
 */
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// In-memory store so the hub is testable without the sqlite native library.
class _FakeStore implements NostrStore {
  final Map<String, NostrEvent> byId = {};
  @override
  bool put(NostrEvent e, {int tier = 2}) {
    if (e.id == null || byId.containsKey(e.id)) return false;
    byId[e.id!] = e;
    return true;
  }

  @override
  List<NostrEvent> query(NostrFilter f) =>
      byId.values.where((e) => NostrWire.matches(f, e)).toList();
}

class _FakeClient implements NostrRelayClient {
  @override
  final String uri;
  _FakeClient(this.uri);

  @override
  NostrEventCallback? onEvent;
  @override
  NostrEoseCallback? onEose;
  @override
  NostrStatusCallback? onStatus;

  final List<String> subscribed = [];
  final List<NostrEvent> published = [];
  @override
  NostrRelayStatus status = NostrRelayStatus.connected;

  @override
  Future<void> connect() async {}
  @override
  void subscribe(String subId, List<NostrFilter> filters) =>
      subscribed.add(subId);
  @override
  void unsubscribe(String subId) {}
  @override
  Future<bool> publish(NostrEvent event) async {
    published.add(event);
    return true;
  }

  @override
  Future<void> close() async {}

  /// Simulate a relay pushing an event to this client's subscription.
  void inject(String subId, NostrEvent e) => onEvent?.call(subId, e);
}

NostrEvent _signed(NostrKeyPair kp,
    {int kind = 1, String content = 'hi', int at = 1700000000}) {
  final e = NostrEvent(
      pubkey: kp.publicKeyHex,
      createdAt: at,
      kind: kind,
      tags: const [],
      content: content);
  e.sign(kp.privateKeyHex);
  return e;
}

void main() {
  late Directory dir;
  late String persist;
  late _FakeStore store;
  final kp = NostrCrypto.generateKeyPair();

  setUp(() {
    dir = Directory.systemTemp.createTempSync('nostrhub');
    persist = '${dir.path}/relays.json';
    store = _FakeStore();
    // Seed the list with local + one rns relay so init() does NOT pull the
    // wss:// defaults (which would open real sockets).
    File(persist).writeAsStringSync(
        '[{"uri":"local"},{"uri":"rns://${'a' * 64}"}]');
  });

  tearDown(() {
    dir.deleteSync(recursive: true);
  });

  NostrRelayHub _hub(_FakeClient fake, {void Function(NostrEvent)? onStored}) =>
      NostrRelayHub(
        store: store,
        persistPath: persist,
        rnsClientFactory: (uri) => fake,
        onStored: onStored,
      );

  test('init loads persisted relays + builds a client per endpoint', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();
    final list = hub.relaysJson();
    expect(list.map((e) => e['uri']), containsAll(['local', fake.uri]));
    expect(list.firstWhere((e) => e['uri'] == fake.uri)['scheme'], 'reticulum');
    expect(list.firstWhere((e) => e['uri'] == 'local')['scheme'], 'local');
    await hub.close();
  });

  test('subscribe answers from local store AND fans to the rns transport',
      () async {
    final backlog = _signed(kp, content: 'stored', at: 1700000001);
    store.put(backlog);
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();

    final sub = hub.subscribe([NostrFilter(authors: [kp.publicKeyHex])]);
    // Local backlog reached the wapp inbox synchronously.
    final drained = hub.drainEvents(sub);
    expect(drained.map((e) => e['content']), contains('stored'));
    // The rns transport got the same subscription.
    expect(fake.subscribed, contains(sub));
    await hub.close();
  });

  test('an inbound event merges into the store and buffers once per sub',
      () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final stored = <NostrEvent>[];
    final hub = _hub(fake, onStored: stored.add);
    await hub.init();
    final sub = hub.subscribe([const NostrFilter(kinds: [1])]);
    hub.drainEvents(sub); // clear any local backlog

    final e = _signed(kp, content: 'live', at: 1700000002);
    fake.inject(sub, e);
    fake.inject(sub, e); // duplicate from another relay → delivered once

    expect(store.query(NostrFilter(ids: [e.id!])).length, 1);
    expect(stored.where((s) => s.id == e.id).length, 1);
    final drained = hub.drainEvents(sub);
    expect(drained.length, 1);
    expect(drained.single['content'], 'live');
    await hub.close();
  });

  test('publish writes to the store and fans to the transport', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();
    final e = _signed(kp, content: 'mine', at: 1700000003);
    await hub.publish(e);
    expect(store.query(NostrFilter(ids: [e.id!])).length, 1);
    expect(fake.published.single.id, e.id);
    await hub.close();
  });

  test('addRelay validates scheme + persists; removeRelay drops it', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();

    expect(hub.addRelay('wss://relay.example.com'), true);
    expect(hub.addRelay('wss://relay.example.com'), false); // dup
    expect(hub.addRelay('gopher://nope'), false); // unknown scheme
    expect(File(persist).readAsStringSync(), contains('relay.example.com'));

    expect(hub.removeRelay('wss://relay.example.com'), true);
    expect(File(persist).readAsStringSync(), isNot(contains('relay.example.com')));
    await hub.close();
  });
}
