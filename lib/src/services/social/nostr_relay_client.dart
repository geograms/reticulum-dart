/*
 * NostrRelayClient — the transport abstraction.
 *
 * A "relay" is anything you can send a REQ / EVENT to and receive EVENT / EOSE /
 * OK back from. The TRANSPORT varies and is chosen by the endpoint URI scheme:
 *   wss:// | ws://   → internet WebSocket   (NostrWsClient)
 *   rns://<idhex>    → Reticulum relay      (NostrRnsClient, wraps RelayNode)
 *   local            → this device          (NostrLocalClient, RelayEventStore)
 *
 * The NostrRelayHub owns a list of these and never cares which transport a given
 * client is — so a new transport is one new implementation, zero changes above.
 */
import '../../util/nostr_event.dart';
import 'relay_event_store.dart' show NostrFilter;

enum NostrRelayStatus { disconnected, connecting, connected, error }

/// Callbacks a client raises to its owner (the hub).
typedef NostrEventCallback = void Function(String subId, NostrEvent event);
typedef NostrEoseCallback = void Function(String subId);
typedef NostrStatusCallback = void Function(NostrRelayStatus status);

abstract class NostrRelayClient {
  /// The endpoint URI this client serves (wss://…, rns://…, local).
  String get uri;

  NostrRelayStatus get status;

  /// Set by the hub before [connect]; the client calls these as data arrives.
  NostrEventCallback? onEvent;
  NostrEoseCallback? onEose;
  NostrStatusCallback? onStatus;

  /// Open / begin maintaining the connection. Idempotent.
  Future<void> connect();

  /// Open a subscription. Matching stored + live events arrive via [onEvent];
  /// [onEose] fires once the stored backlog is delivered.
  void subscribe(String subId, List<NostrFilter> filters);

  /// Cancel a subscription.
  void unsubscribe(String subId);

  /// Publish an event. Returns true if the transport accepted it for delivery
  /// (not necessarily that a remote relay stored it — that arrives as OK).
  Future<bool> publish(NostrEvent event);

  /// Tear down.
  Future<void> close();
}

/// The transport an endpoint URI selects.
enum NostrTransport { websocket, reticulum, local, unknown }

NostrTransport nostrTransportOf(String uri) {
  final u = uri.trim().toLowerCase();
  if (u == 'local' || u.startsWith('local')) return NostrTransport.local;
  if (u.startsWith('wss://') || u.startsWith('ws://')) {
    return NostrTransport.websocket;
  }
  if (u.startsWith('rns://')) return NostrTransport.reticulum;
  return NostrTransport.unknown;
}
