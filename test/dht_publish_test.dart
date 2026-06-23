/*
 * Locks the DHT publish fix: a provider must keep its OWN provider record locally
 * even when it has peers, so content it holds stays discoverable when querying it
 * directly — even if every replication STORE to the k-closest peers fails. This
 * was the root cause of "resolved 0 providers" between two meshed devices: the
 * publisher replicated to nobody (flaky paths) AND kept nothing.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  group('DhtNode.publish keeps the publisher authoritative', () {
    test('keeps its own record when replication STOREs all fail', () async {
      final me = await RnsIdentity.generate();
      // sendRpc always fails (no peer is reachable) — models flaky paths.
      final node = DhtNode(identity: me, sendRpc: (to, req) async => null);
      // Give it peers so it's NOT the isolated-network case.
      for (var i = 0; i < 3; i++) {
        node.routing.add(DhtContact.ofIdentity(await RnsIdentity.generate()));
      }
      expect(node.storedKeys, 0);

      final sha = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final rec = await ProviderRecord.create(providerIdentity: me, sha256: sha);
      final holders = await node.publish(rec);

      expect(holders, greaterThanOrEqualTo(1),
          reason: 'the publisher counts as a holder of its own record');
      expect(node.storedKeys, 1, reason: 'record kept locally despite failed STOREs');

      // Querying this node (as a resolver would) returns the record.
      final got = await node.resolve(sha);
      expect(got, isNotEmpty);
      expect(got.first.sha256, equals(sha));
    });

    test('a resolver gets the record by querying the holder directly', () async {
      // Two nodes: holder publishes, resolver has only the holder in its routing
      // and must learn the provider by asking it (FIND_VALUE).
      final holderId = await RnsIdentity.generate();
      final resolverId = await RnsIdentity.generate();
      late DhtNode holder;
      late DhtNode resolver;
      holder = DhtNode(
          identity: holderId,
          sendRpc: (to, req) async => null); // holder needs no outbound peers
      resolver = DhtNode(
        identity: resolverId,
        // The resolver's RPC routes straight to the holder's responder.
        sendRpc: (to, req) async =>
            DhtMessage.decode((await holder.handle(req)).encode()),
      );
      resolver.routing.add(DhtContact.ofIdentity(holderId));

      final sha = Uint8List.fromList(List<int>.generate(32, (i) => 255 - i));
      final rec =
          await ProviderRecord.create(providerIdentity: holderId, sha256: sha);
      await holder.publish(rec);

      final got = await resolver.resolve(sha);
      expect(got, isNotEmpty, reason: 'resolver must find the holder by asking it');
      expect(got.first.providerIdentity.hexHash, holderId.hexHash);
    });
  });
}
