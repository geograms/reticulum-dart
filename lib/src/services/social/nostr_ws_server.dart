/*
 * NostrWsServer — makes THIS device a standard wss:// NOSTR relay.
 *
 * An HttpServer that upgrades WebSocket connections and speaks the NIP-01 JSON
 * wire against the local RelayEventStore, so any off-the-shelf NOSTR client on
 * the LAN (or reachable over the network) can use this device as a relay:
 *   - ["REQ", subId, filter…]  → stored events + ["EOSE", subId], sub kept open
 *   - ["EVENT", event]         → store.put + ["OK", id, accepted, msg]
 *   - ["CLOSE", subId]         → drop the sub
 * Freshly stored events (from this device OR ingested over other transports) are
 * LIVE-pushed to every open sub whose filter matches, via [broadcast].
 *
 * Bind pattern mirrors blossom_server.dart (HttpServer.bind on 0.0.0.0).
 */
import 'dart:async';
import 'dart:io';

import '../../util/nostr_event.dart';
import 'nostr_wire.dart';
import 'relay_event_store.dart';

class _Conn {
  final WebSocket ws;
  final Map<String, List<NostrFilter>> subs = {};
  _Conn(this.ws);
}

class NostrWsServer {
  final RelayEventStore store;
  final int port;
  final void Function(String msg)? log;

  NostrWsServer(this.store, {this.port = 4848, this.log});

  HttpServer? _http;
  final Set<_Conn> _conns = {};

  bool get running => _http != null;
  int get connections => _conns.length;

  Future<bool> start() async {
    if (_http != null) return true;
    try {
      _http = await HttpServer.bind(InternetAddress.anyIPv4, port, shared: true);
      _http!.listen(_onRequest, onError: (Object e) => log?.call('ws srv: $e'));
      log?.call('NOSTR wss server on :$port');
      return true;
    } catch (e) {
      log?.call('NOSTR wss server bind failed: $e');
      return false;
    }
  }

  Future<void> _onRequest(HttpRequest req) async {
    if (!WebSocketTransformer.isUpgradeRequest(req)) {
      // NIP-11 relay information document on a plain GET, so clients can probe.
      req.response
        ..statusCode = HttpStatus.ok
        ..headers.contentType = ContentType('application', 'nostr+json')
        ..write('{"name":"geogram","supported_nips":[1,9,11,50],'
            '"software":"geogram-aurora"}');
      await req.response.close();
      return;
    }
    try {
      final ws = await WebSocketTransformer.upgrade(req);
      final conn = _Conn(ws);
      _conns.add(conn);
      ws.listen(
        (data) => _onFrame(conn, data is String ? data : data.toString()),
        onDone: () => _conns.remove(conn),
        onError: (Object e) => _conns.remove(conn),
        cancelOnError: true,
      );
    } catch (e) {
      log?.call('ws upgrade failed: $e');
    }
  }

  void _onFrame(_Conn c, String raw) {
    final msg = NostrWire.decode(raw);
    if (msg == null) return;
    switch (msg) {
      case NostrReqMsg(:final subId, :final filters):
        c.subs[subId] = filters;
        for (final f in filters) {
          for (final e in store.query(f)) {
            _send(c, NostrWire.eventFor(subId, e));
          }
        }
        _send(c, NostrWire.eose(subId));
      case NostrPublishMsg(:final event):
        final ok = event.verify() && store.put(event);
        _send(c, NostrWire.ok(event.id ?? '', ok, ok ? '' : 'invalid'));
        if (ok) broadcast(event);
      case NostrCloseMsg(:final subId):
        c.subs.remove(subId);
      default:
        break;
    }
  }

  /// LIVE-push a stored event to every open sub whose filter matches. Called by
  /// the hub after it merges an event from ANY transport, so this relay's
  /// subscribers see mesh/internet events too.
  void broadcast(NostrEvent event) {
    for (final c in _conns) {
      for (final e in c.subs.entries) {
        if (e.value.any((f) => NostrWire.matches(f, event))) {
          _send(c, NostrWire.eventFor(e.key, event));
          break;
        }
      }
    }
  }

  void _send(_Conn c, String frame) {
    try {
      c.ws.add(frame);
    } catch (_) {
      _conns.remove(c);
    }
  }

  Future<void> stop() async {
    for (final c in _conns) {
      try {
        await c.ws.close();
      } catch (_) {}
    }
    _conns.clear();
    await _http?.close(force: true);
    _http = null;
  }
}
