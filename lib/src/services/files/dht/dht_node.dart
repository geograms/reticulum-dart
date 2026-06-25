/*
 * DhtNode — the Kademlia engine: a routing table, a local record store, and the
 * iterative FIND_NODE / FIND_VALUE / STORE algorithms plus publish() and
 * resolve(). Transport-agnostic: the owner supplies [sendRpc] (send a DhtMessage
 * to a contact, await the reply) — in-process for tests, or over a Reticulum link
 * in the live node. handle()/handleEncoded() implement the responder side.
 *
 * resolve(sha256) is what an edge client's entry node runs on its behalf:
 * recursively walk to the nodes closest to the file key, collecting verified,
 * unexpired provider records, ranked by capacity class (best providers first).
 */
import 'dart:async';
import 'dart:typed_data';

import '../../reticulum/rns_identity.dart';
import 'dht_core.dart';
import 'dht_message.dart';
import 'provider_record.dart';
import 'routing_table.dart';

/// Send a DHT message to [to] and await the reply (null on failure/timeout).
typedef DhtRpc = Future<DhtMessage?> Function(DhtContact to, DhtMessage req);

class DhtNode {
  final RnsIdentity identity; // full identity (private) — to sign nothing here,
  // but it identifies us; records are signed by the provider, not the DHT node.
  final int k;
  final int alpha;
  final DhtRpc sendRpc;
  final void Function(String msg)? log;

  late final Uint8List myId = DhtContact.ofIdentity(identity).id;
  late final Uint8List myPub = identity.getPublicKey();
  late final RoutingTable routing = RoutingTable(myId, k: k);

  // fileKey(16B) hex -> provider records this node custodies.
  final Map<String, List<ProviderRecord>> _store = {};

  DhtNode({
    required this.identity,
    this.k = 8,
    this.alpha = 3,
    required this.sendRpc,
    this.log,
  });

  int get storedKeys => _store.length;

  /// How many provider records we have accepted from OTHER nodes (replicas) —
  /// the live signal that replication is actually landing on this node, as
  /// opposed to records we published about our own content.
  int replicasStored = 0;

  // ── Responder side ───────────────────────────────────────────────────────
  Future<DhtMessage> handle(DhtMessage req) async {
    routing.add(req.sender); // learn whoever contacts us
    switch (req.op) {
      case DhtOp.ping:
        return DhtMessage.pong(myPub);
      case DhtOp.findNode:
        return DhtMessage.nodes(
            myPub, _cap(routing.closest(req.target!, k), kDhtWireMaxContacts));
      case DhtOp.findValue:
        final key = dhtFileKey(req.sha!);
        final recs = _liveRecords(key, req.sha!);
        return recs.isNotEmpty
            ? DhtMessage.valueRecords(myPub, _cap(recs, kDhtWireMaxRecords))
            : DhtMessage.valueNodes(
                myPub, _cap(routing.closest(key, k), kDhtWireMaxContacts));
      case DhtOp.store:
        final r = req.records.first;
        final ok = await _accept(r);
        if (ok && !_eq(r.providerPub, myPub)) {
          replicasStored++;
          log?.call('stored replica ${dhtHex(r.sha256).substring(0, 8)} from '
              '${dhtHex(r.providerPub).substring(0, 8)} (replication landed)');
        }
        return DhtMessage.storeOk(myPub, ok);
      default:
        return DhtMessage.pong(myPub);
    }
  }

  /// Wire entry point for the live transport.
  Future<Uint8List?> handleEncoded(Uint8List raw) async {
    final m = DhtMessage.decode(raw);
    if (m == null) return null;
    return (await handle(m)).encode();
  }

  // ── Initiator side ─────────────────────────────────────────────────────────
  /// Seed the routing table and warm it by looking ourselves up.
  Future<void> bootstrap(List<DhtContact> seeds) async {
    for (final s in seeds) {
      routing.add(s);
    }
    await iterativeFindNode(myId);
  }

  /// Enough confirmed replicas for solid redundancy. Once this many peers ACK a
  /// STORE, publish() returns without waiting for the rest to answer (or to time
  /// out) — k is sized to cover the whole overlay (most of which is unreachable
  /// or slow), so waiting for all of them just stalled publish and undercounted.
  static const int targetReplicas = 8;

  /// Publish a signed provider record at the nodes closest to its file key.
  /// Returns how many peers CONFIRMED storing it (plus self).
  Future<int> publish(ProviderRecord r) async {
    final closest = await iterativeFindNode(r.fileKey);
    // Fan the STOREs out concurrently, but return as soon as [targetReplicas]
    // peers have ACKed — don't block on the long tail. Two reasons this matters:
    // (a) the k-closest is most of the overlay, much of it unreachable/slow, so
    // waiting for every STORE to answer-or-time-out stalled publish for the full
    // RPC timeout on each dead-but-routable contact; (b) a STORE ACK arrives a
    // full extra round-trip after the data is already stored, so under the old
    // tight wait the ACKs landed AFTER we'd given up — publish logged
    // "1 holders" even though replication had succeeded. The in-flight STOREs we
    // don't wait for still complete in the background and still land their
    // records (more replicas = better); we just stop COUNTING once we have enough.
    var ok = 0;
    final enough = Completer<void>();
    var pending = closest.length;
    for (final c in closest) {
      // Detached on purpose: survives past the early return to keep replicating.
      // ignore: discarded_futures
      () async {
        routing.add(c);
        final resp = await sendRpc(c, DhtMessage.store(myPub, r));
        if (resp != null && resp.op == DhtOp.storeOk && resp.ok) {
          if (++ok >= targetReplicas && !enough.isCompleted) enough.complete();
        }
        if (--pending == 0 && !enough.isCompleted) enough.complete();
      }();
    }
    if (closest.isNotEmpty) await enough.future;
    // ALWAYS keep our own record locally: we are authoritative for content we
    // hold, so a resolver that queries us (we're in its routing) must get it even
    // if every replication STORE to the k-closest failed. Previously we stored
    // locally only when isolated (closest.isEmpty), so a publisher with peers but
    // flaky paths replicated to nobody AND kept nothing — its file became
    // undiscoverable despite it sitting right there. That was the root cause of
    // "resolved 0 providers" between two meshed devices.
    final keptSelf = await _accept(r);
    final confirmed = ok; // peers that ACKed by the time we returned
    if (keptSelf && ok == 0) ok = 1;
    log?.call('publish ${dhtHex(r.sha256).substring(0, 8)} -> $confirmed peer '
        'replica(s)${keptSelf ? ' +self' : ''}');
    return ok;
  }

  /// Resolve a file id to its providers (verified, unexpired), best class first.
  Future<List<ProviderRecord>> resolve(Uint8List sha256) async {
    final target = dhtFileKey(sha256);
    final found = <String, ProviderRecord>{}; // providerPub hex -> record
    for (final r in _liveRecords(target, sha256)) {
      found[dhtHex(r.providerPub)] = r;
    }
    await _iterate(
      target,
      makeReq: () => DhtMessage.findValue(myPub, sha256),
      onResponse: (resp) async {
        if (!resp.hasValue) return;
        for (final r in resp.records) {
          if (!_eq(r.sha256, sha256) || r.isExpired()) continue;
          if (!await r.verify()) continue;
          found[dhtHex(r.providerPub)] = r;
        }
      },
      // FIND_VALUE short-circuits: the moment a queried node returns a verified
      // record, stop the lookup. Without this, resolve ground through all k
      // contacts (8 s timeout each) even after the value was in hand on round 1
      // — the cause of the multi-minute "check for updates" hang when most
      // contacts were stale. We still keep the whole round that found it, so a
      // resolver gets several providers (redundancy), not just the first.
      stopEarly: () => found.isNotEmpty,
    );
    final list = found.values.toList()
      ..sort((a, b) => a.capacity.compareTo(b.capacity));
    return list;
  }

  /// Find the k contacts closest to [target] (iterative).
  Future<List<DhtContact>> iterativeFindNode(Uint8List target) async {
    final shortlist = await _iterate(target, makeReq: null, onResponse: null);
    return shortlist;
  }

  /// Core iterative lookup. With [makeReq]/[onResponse] it does FIND_VALUE
  /// (collecting via onResponse), else FIND_NODE. Returns the k closest contacts
  /// discovered.
  Future<List<DhtContact>> _iterate(
    Uint8List target, {
    DhtMessage Function()? makeReq,
    Future<void> Function(DhtMessage resp)? onResponse,
    bool Function()? stopEarly,
  }) async {
    final shortlist = <String, DhtContact>{};
    for (final c in routing.closest(target, k)) {
      shortlist[c.idHex] = c;
    }
    final queried = <String>{};
    final failed = <String>{};
    int cmp(DhtContact a, DhtContact b) =>
        dhtCompare(dhtXor(a.id, target), dhtXor(b.id, target));

    for (var round = 0; round < 24; round++) {
      final candidates = shortlist.values
          .where((c) => !queried.contains(c.idHex) && !failed.contains(c.idHex))
          .toList()
        ..sort(cmp);
      if (candidates.isEmpty) break;
      final batch = candidates.take(alpha).toList();
      final results = await Future.wait(batch.map((c) async {
        queried.add(c.idHex);
        final req = makeReq != null
            ? makeReq()
            : DhtMessage.findNode(myPub, target);
        final resp = await sendRpc(c, req);
        return MapEntry(c, resp);
      }));
      var improved = false;
      for (final e in results) {
        final resp = e.value;
        if (resp == null) {
          failed.add(e.key.idHex);
          continue;
        }
        routing.add(e.key);
        if (onResponse != null) await onResponse(resp);
        for (final nc in resp.contacts) {
          if (dhtIdEquals(nc.id, myId)) continue;
          routing.add(nc);
          if (!shortlist.containsKey(nc.idHex)) {
            shortlist[nc.idHex] = nc;
            improved = true;
          }
        }
      }
      // FIND_VALUE early termination: the value was found this round, stop now
      // rather than walking the rest of the (possibly stale, slow) shortlist.
      if (stopEarly?.call() ?? false) break;
      final top = (shortlist.values.toList()..sort(cmp)).take(k);
      if (top.every((c) => queried.contains(c.idHex) || failed.contains(c.idHex))) {
        break;
      }
      if (!improved && batch.length < alpha) break;
    }
    final out = shortlist.values.toList()..sort(cmp);
    return out.take(k).toList();
  }

  // ── Local store ────────────────────────────────────────────────────────────
  Future<bool> _accept(ProviderRecord r) async {
    if (r.isExpired()) return false;
    if (!await r.verify()) return false;
    final key = dhtHex(r.fileKey);
    final list = _store.putIfAbsent(key, () => <ProviderRecord>[]);
    list.removeWhere((e) => _eq(e.providerPub, r.providerPub));
    list.add(r);
    return true;
  }

  List<ProviderRecord> _liveRecords(Uint8List fileKey16, Uint8List sha256) {
    final key = dhtHex(fileKey16);
    final list = _store[key];
    if (list == null) return const [];
    list.removeWhere((r) => r.isExpired());
    if (list.isEmpty) {
      _store.remove(key);
      return const [];
    }
    return list.where((r) => _eq(r.sha256, sha256)).toList();
  }

  // Cap a list so a NODES/VALUE response fits one ~450B link-encrypted packet
  // (no per-RPC fragmentation needed). Routing still uses the full k internally.
  static List<T> _cap<T>(List<T> xs, int n) =>
      xs.length <= n ? xs : xs.sublist(0, n);

  static bool _eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
