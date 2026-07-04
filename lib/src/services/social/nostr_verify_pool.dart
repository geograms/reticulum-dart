/*
 * NostrVerifyPool — moves NOSTR signature verification (BIP-340 Schnorr, the
 * CPU-heavy part of ingesting a relay feed) OFF the UI/engine isolate onto a
 * dedicated background isolate.
 *
 * A public relay firehose delivers hundreds of kind-1 events per second; doing
 * a Schnorr verify (and then a SQLite write) synchronously inside the WebSocket
 * stream listener starves the event loop and makes the whole app sluggish. Here
 * the listener only enqueues the raw frame; a single long-lived isolate decodes
 * + verifies it and reports back the ones that pass. A hard cap on in-flight
 * work means a firehose is sampled, not queued unboundedly, so memory and the
 * main thread both stay bounded no matter how fast events arrive.
 *
 * Pure Dart (pointycastle) crypto, so it runs in a plain isolate with no FFI or
 * platform channels — safe in the headless Android background engine too.
 */
import 'dart:async';
import 'dart:isolate';

import 'nostr_wire.dart';

/// A verified frame handed back to the caller: the subscription id and the raw
/// event JSON (the caller re-decodes — cheap — and dispatches it).
typedef VerifiedEvent = ({String subId, String raw});

class NostrVerifyPool {
  NostrVerifyPool._();
  static final NostrVerifyPool instance = NostrVerifyPool._();

  Isolate? _iso;
  SendPort? _tx;
  final ReceivePort _rx = ReceivePort();
  bool _starting = false;
  final List<Completer<void>> _waiters = [];

  /// In-flight frames sent to the isolate but not yet answered. Bounds memory
  /// and CPU: once this many are outstanding, new frames are DROPPED (a
  /// firehose is a sample, not a queue) rather than piling up.
  static const int _maxInFlight = 256;
  int _inFlight = 0;

  int _seq = 0;
  // seq → the callback to run if the event verifies.
  final Map<int, void Function()> _pending = {};

  /// Drop counter (for a periodic "sampled N" log by the caller if wanted).
  int dropped = 0;

  Future<void> _ensureStarted() async {
    if (_tx != null) return;
    if (_starting) {
      final c = Completer<void>();
      _waiters.add(c);
      return c.future;
    }
    _starting = true;
    _rx.listen(_onFromIsolate);
    _iso = await Isolate.spawn(_isolateMain, _rx.sendPort,
        debugName: 'nostr-verify');
    // The first message from the isolate is its inbound SendPort.
  }

  void _onFromIsolate(dynamic msg) {
    if (msg is SendPort) {
      _tx = msg;
      _starting = false;
      for (final w in _waiters) {
        if (!w.isCompleted) w.complete();
      }
      _waiters.clear();
      return;
    }
    // Result: [seq, ok].
    if (msg is List && msg.length == 2) {
      final seq = msg[0] as int;
      final ok = msg[1] as bool;
      _inFlight--;
      final cb = _pending.remove(seq);
      if (ok && cb != null) cb();
    }
  }

  /// Verify [raw] off-thread; run [onValid] on this isolate if it passes. Drops
  /// (and counts) the frame if the pool is saturated. Fire-and-forget.
  void verify(String raw, void Function() onValid) {
    if (_inFlight >= _maxInFlight) {
      dropped++;
      return;
    }
    final tx = _tx;
    final seq = _seq++;
    _pending[seq] = onValid;
    _inFlight++;
    if (tx == null) {
      // Not started yet — start, then send once the port is ready.
      // ignore: discarded_futures
      _ensureStarted().then((_) => _tx?.send([seq, raw]));
      return;
    }
    tx.send([seq, raw]);
  }

  void dispose() {
    _iso?.kill(priority: Isolate.immediate);
    _iso = null;
    _tx = null;
    _rx.close();
    _pending.clear();
    _inFlight = 0;
  }

  // ── isolate side ──────────────────────────────────────────────────────────
  static void _isolateMain(SendPort tx) {
    final rx = ReceivePort();
    tx.send(rx.sendPort);
    rx.listen((dynamic msg) {
      if (msg is! List || msg.length != 2) return;
      final seq = msg[0] as int;
      final raw = msg[1] as String;
      var ok = false;
      try {
        final decoded = NostrWire.decode(raw);
        if (decoded is NostrEventMsg) ok = decoded.event.verify();
      } catch (_) {
        ok = false;
      }
      tx.send([seq, ok]);
    });
  }
}
