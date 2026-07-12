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
  final Map<String, Set<String>> reactions = {};
  @override
  bool put(NostrEvent e, {int tier = 2}) {
    if (e.id == null || byId.containsKey(e.id)) return false;
    byId[e.id!] = e;
    return true;
  }

  @override
  List<NostrEvent> query(NostrFilter f) =>
      byId.values.where((e) => NostrWire.matches(f, e)).toList();

  @override
  bool addReaction(String eventId, String pubkey) =>
      reactions.putIfAbsent(eventId, () => <String>{}).add(pubkey);

  @override
  List<String> reactionPubkeys(String eventId) =>
      reactions[eventId]?.toList() ?? const [];

  @override
  List<String> replyIdsFor(String eventId) => [
        for (final e in byId.values)
          if (e.kind == 1 &&
              e.tags
                  .any((t) => t.length >= 2 && t[0] == 'e' && t[1] == eventId))
            e.id!,
      ];
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

  // ── The live firehose (the "All" tab) ─────────────────────────────────────

  test('the firehose delivers a fresh post immediately — no likes required',
      () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();

    final sub = hub.subscribeFirehose(requireProfile: false);
    final relaySub = fake.subscribed.last;

    fake.inject(relaySub, _signed(kp, content: 'a post nobody has liked yet'));

    expect(hub.drainEvents(sub).map((e) => e['content']),
        ['a post nobody has liked yet'],
        reason: 'this is the whole point: discovery can only show posts old '
            'enough to have gathered likes, so it can never be the All tab');
    await hub.close();
  });

  test('the firehose drops spam before it is ever stored', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();

    final sub = hub.subscribeFirehose(requireProfile: false);
    final relaySub = fake.subscribed.last;

    fake.inject(
        relaySub,
        _signed(kp,
            content: 'https://spam.example/a https://spam.example/b',
            at: 1700000002));

    expect(hub.drainEvents(sub), isEmpty);
    expect(store.byId.values.any((e) => e.content.startsWith('https://spam')),
        isFalse,
        reason: 'a public firehose must not write junk into sqlite all day');
    await hub.close();
  });

  test('a post from an unknown author waits for their profile, then appears',
      () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();

    // Strict: the author must have a kind-0 we have seen.
    final sub = hub.subscribeFirehose();
    final relaySub = fake.subscribed.last;

    final author = NostrCrypto.generateKeyPair();
    fake.inject(relaySub,
        _signed(author, content: 'hello, I am new here', at: 1700000003));

    expect(hub.drainEvents(sub), isEmpty, reason: 'held, pending their profile');

    // Their kind-0 arrives on the same subscription (which is why the firehose
    // asks for kind-0 alongside kind-1).
    fake.inject(
        relaySub,
        _signed(author,
            kind: 0, content: '{"name":"newbie"}', at: 1700000004));

    expect(hub.drainEvents(sub).map((e) => e['content']),
        contains('hello, I am new here'),
        reason: 'a new account is not a spammer — their profile was in flight');
    await hub.close();
  });

  // ── The two discovery bugs ────────────────────────────────────────────────

  test('TWO discovery subscribers both get the feed', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();

    // The launcher hero subscribes first, the Social wapp second. The second
    // used to be handed the first one's id, with no inbox behind it — so it
    // drained nothing, forever.
    final hero = hub.subscribeDiscovery(minLikes: 1);
    final wapp = hub.subscribeDiscovery(minLikes: 1);
    expect(hero, isNot(wapp));

    final reactSub = fake.subscribed[fake.subscribed.length - 1];
    final post = _signed(kp, content: 'a popular post', at: 1700000005);

    // One like qualifies it, then the post itself arrives by id.
    final liker = NostrCrypto.generateKeyPair();
    final like = NostrEvent(
      pubkey: liker.publicKeyHex,
      createdAt: 1700000006,
      kind: 7,
      tags: [
        ['e', post.id!]
      ],
      content: '+',
    )..sign(liker.privateKeyHex);
    fake.inject(reactSub, like);
    fake.inject('anySub', post);

    expect(hub.drainEvents(hero).map((e) => e['content']), ['a popular post']);
    expect(hub.drainEvents(wapp).map((e) => e['content']), ['a popular post'],
        reason: 'whoever subscribed SECOND must not get a dead id');
    await hub.close();
  });

  test('unsubscribe then re-subscribe still delivers (pull-to-refresh)',
      () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = _hub(fake);
    await hub.init();

    final first = hub.subscribeDiscovery(minLikes: 1);
    hub.unsubscribe(first); // what pull-to-refresh does

    final second = hub.subscribeDiscovery(minLikes: 1);
    final reactSub = fake.subscribed.last;

    final post = _signed(kp, content: 'after the refresh', at: 1700000007);
    final liker = NostrCrypto.generateKeyPair();
    final like = NostrEvent(
      pubkey: liker.publicKeyHex,
      createdAt: 1700000008,
      kind: 7,
      tags: [
        ['e', post.id!]
      ],
      content: '+',
    )..sign(liker.privateKeyHex);
    fake.inject(reactSub, like);
    fake.inject('anySub', post);

    expect(hub.drainEvents(second).map((e) => e['content']),
        ['after the refresh'],
        reason: 'unsubscribe left _discoFeedSub pointing at the deleted inbox, '
            'so refreshing the feed killed it for the life of the process');
    await hub.close();
  });
}
