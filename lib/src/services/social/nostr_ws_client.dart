/*
 * NostrWsClient — the public internet transport: a NOSTR relay over WebSocket
 * (wss:// / ws://), NIP-01 JSON wire via [NostrWire].
 *
 * Uses package:web_socket_channel so the SAME code runs native (dart:io) and
 * web. Reconnects with capped backoff and replays live subscriptions on
 * reconnect, so a relay flap doesn't silently stop the feed.
 */
import 'dart:async';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../../util/nostr_event.dart';
import 'nostr_relay_client.dart';
import 'nostr_wire.dart';
import 'relay_event_store.dart' show NostrFilter;

class NostrWsClient implements NostrRelayClient {
  @override
  final String uri;
  final void Function(String msg)? log;

  NostrWsClient(this.uri, {this.log});

  @override
  NostrEventCallback? onEvent;
  @override
  NostrEoseCallback? onEose;
  @override
  NostrClosedCallback? onClosed;
  @override
  NostrStatusCallback? onStatus;

  WebSocketChannel? _ch;
  StreamSubscription<dynamic>? _sub;
  NostrRelayStatus _status = NostrRelayStatus.disconnected;
  bool _closed = false;
  Timer? _retry;
  int _backoffMs = 1000;

  // Live subscriptions, replayed on reconnect.
  final Map<String, List<NostrFilter>> _subs = {};
  // Publishes issued while offline, flushed on connect.
  final List<NostrEvent> _pendingPublish = [];

  @override
  NostrRelayStatus get status => _status;

  void _setStatus(NostrRelayStatus s) {
    if (_status == s) return;
    _status = s;
    onStatus?.call(s);
  }

  @override
  Future<void> connect() async {
    if (_closed) return;
    _retry?.cancel();
    if (_status == NostrRelayStatus.connected ||
        _status == NostrRelayStatus.connecting) {
      return;
    }
    _setStatus(NostrRelayStatus.connecting);
    try {
      final ch = WebSocketChannel.connect(Uri.parse(uri));
      _ch = ch;
      // ready throws on a failed handshake (bad TLS / unreachable host).
      await ch.ready;
      _setStatus(NostrRelayStatus.connected);
      _backoffMs = 1000;
      _touch(); // start the idle watchdog for this socket
      _sub = ch.stream.listen(
        _onData,
        onError: (Object e) => _onDown('stream error: $e'),
        onDone: () => _onDown('closed'),
        cancelOnError: true,
      );
      // Replay subscriptions + flush queued publishes.
      for (final e in _subs.entries) {
        _send(NostrWire.req(e.key, e.value));
      }
      for (final e in List<NostrEvent>.from(_pendingPublish)) {
        _send(NostrWire.event(e));
      }
      _pendingPublish.clear();
    } catch (e) {
      _onDown('connect failed: $e');
    }
  }

  // A relay we hold open subscriptions on is never legitimately silent for
  // minutes: even a quiet one answers a REQ with EOSE. Silence with the socket
  // still "connected" is a half-open TCP — the phone changed network, or a
  // carrier NAT dropped the flow — and nothing else in the stack notices,
  // because there is no error to notice. Re-opening the SUBSCRIPTION (which the
  // firehose watchdog does) cannot help: the frames go into a dead socket.
  static const int _idleMs = 90 * 1000;
  Timer? _idle;

  void _touch() {
    _idle?.cancel();
    _idle = Timer(const Duration(milliseconds: _idleMs), () {
      if (_closed || _status != NostrRelayStatus.connected) return;
      _onDown('idle ${_idleMs ~/ 1000}s — socket is dead, reconnecting');
    });
  }

  void _onData(dynamic data) {
    _touch();
    final raw = data is String ? data : data.toString();
    final msg = NostrWire.decode(raw);
    if (msg == null) return;
    switch (msg) {
      case NostrEventMsg(:final subId, :final event):
        // Verify inline — this client runs inside the NostrEngine background
        // isolate, so Schnorr never touches the UI isolate.
        if (event.verify()) onEvent?.call(subId, event);
      case NostrEoseMsg(:final subId):
        onEose?.call(subId);
      case NostrNoticeMsg(:final message):
        log?.call('$uri notice: $message');
      case NostrClosedMsg(:final subId, :final message):
        // The relay REFUSED a subscription (rate-limited, too many filters,
        // auth-required…). Swallowing this is how a feed dies in silence: the
        // REQ is on the wire, no error is raised, and nothing ever arrives.
        log?.call('$uri CLOSED $subId: $message');
        onClosed?.call(subId, message);
      case NostrOkMsg():
      case NostrReqMsg():
      case NostrCloseMsg():
      case NostrPublishMsg():
        break; // client side ignores server-ingest frames
    }
  }

  void _onDown(String why) {
    if (_closed) return;
    _idle?.cancel();
    _idle = null;
    _setStatus(NostrRelayStatus.error);
    _sub?.cancel();
    _sub = null;
    _ch = null;
    log?.call('$uri down: $why');
    // Reconnect with capped exponential backoff; live subs are replayed above.
    _retry?.cancel();
    _retry = Timer(Duration(milliseconds: _backoffMs), () {
      _backoffMs = (_backoffMs * 2).clamp(1000, 60000);
      connect();
    });
  }

  void _send(String frame) {
    final ch = _ch;
    if (ch == null || _status != NostrRelayStatus.connected) return;
    try {
      ch.sink.add(frame);
    } catch (e) {
      _onDown('send failed: $e');
    }
  }

  @override
  void subscribe(String subId, List<NostrFilter> filters) {
    _subs[subId] = filters;
    log?.call('$uri: REQ $subId (${_subs.length} open)');
    if (_status == NostrRelayStatus.connected) {
      _send(NostrWire.req(subId, filters));
    } else {
      connect();
    }
  }

  @override
  void unsubscribe(String subId) {
    _subs.remove(subId);
    _send(NostrWire.close(subId));
  }

  @override
  Future<bool> publish(NostrEvent event) async {
    if (_status == NostrRelayStatus.connected) {
      _send(NostrWire.event(event));
    } else {
      _pendingPublish.add(event); // flushed on next connect
      connect();
    }
    return true;
  }

  @override
  Future<void> close() async {
    _closed = true;
    _idle?.cancel();
    _idle = null;
    _retry?.cancel();
    await _sub?.cancel();
    try {
      await _ch?.sink.close();
    } catch (_) {}
    _ch = null;
    _setStatus(NostrRelayStatus.disconnected);
  }
}
