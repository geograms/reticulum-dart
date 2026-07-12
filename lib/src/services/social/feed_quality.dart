/*
 * feed_quality — what a public NOSTR firehose is allowed to put in front of a
 * user.
 *
 * The "All" tab exists to DISCOVER people worth following, which means it has to
 * carry strangers, which means it carries whatever strangers post. Public relays
 * are full of link-dropping bots, hashtag walls and copy-paste rings. A raw
 * firehose is unusable; a like-gated one is not a firehose at all (it can only
 * show posts old enough to have gathered likes — which is the bug this replaces).
 *
 * So: show everything, quickly, EXCEPT what fails a cheap, explainable gate.
 *
 * Two halves, deliberately split:
 *
 *   * [contentVerdict] — pure. One event, one answer, no state, no clock. Every
 *     rule here is a property of the text itself. Unit-testable exhaustively,
 *     and the place to look when something is wrongly hidden.
 *   * [FirehoseFilter] — the stateful half: duplicate detection across authors,
 *     per-author flood rate, and the pending-profile buffer. Bounded caches, no
 *     unbounded growth on a feed that never stops.
 *
 * The bias throughout is that a FALSE POSITIVE IS WORSE THAN A MISS. Hiding a
 * real person's post is invisible to the user and unfixable by them; letting one
 * spam post through costs a moment's annoyance. Where a rule is uncertain, it
 * lets the post through.
 */
import 'dart:collection';

import '../../util/nostr_event.dart';

enum FeedDrop {
  empty,
  hashtagStuffing,
  linkOnly,
  symbolDominant,
  duplicate,
  flooding,
  muted,
  noProfile,
}

sealed class FeedVerdict {
  const FeedVerdict();
}

class FeedKeep extends FeedVerdict {
  const FeedKeep();
}

class FeedReject extends FeedVerdict {
  final FeedDrop reason;
  const FeedReject(this.reason);
}

/// The author has no profile YET. Not a rejection: held briefly in case their
/// kind-0 is still in flight (the firehose subscribes to kind-0 for exactly this
/// reason). Released when the profile lands, forgotten when it doesn't.
class FeedPending extends FeedVerdict {
  const FeedPending();
}

// ── Pure content rules ──────────────────────────────────────────────────────

final RegExp _url = RegExp(r'https?://\S+', caseSensitive: false);
final RegExp _hashtag = RegExp(r'(?:^|\s)#[^\s#]+');
final RegExp _mention = RegExp(r'nostr:[a-z0-9]+', caseSensitive: false);
final RegExp _whitespace = RegExp(r'\s+');

/// Rules that depend only on the post's text.
FeedVerdict contentVerdict(String content) {
  final text = content.trim();
  if (text.length < 2) return const FeedReject(FeedDrop.empty);

  final tags = _hashtag.allMatches(text).length;
  final withoutTags = text.replaceAll(_hashtag, ' ');
  final urls = _url.allMatches(text).length;

  // What is left once the machinery is stripped out: no links, no hashtags, no
  // nostr: mentions. This is the part a human actually wrote.
  final prose = withoutTags
      .replaceAll(_url, ' ')
      .replaceAll(_mention, ' ')
      .replaceAll(_whitespace, ' ')
      .trim();

  // A wall of hashtags with a few words wedged between them. Note the second
  // clause needs prose to be short too — "#nostr #bitcoin" under a real
  // paragraph is normal, and must survive.
  final words = prose.isEmpty ? 0 : prose.split(' ').length;
  if (tags > 5 && words < tags) {
    return const FeedReject(FeedDrop.hashtagStuffing);
  }

  // Links are fine. A post that is ONLY links is an advert.
  if (urls > 0 && prose.isEmpty) return const FeedReject(FeedDrop.linkOnly);

  // Emoji/symbol soup: little or no letters, mostly pictures. Counting letters
  // (rather than trying to enumerate emoji) is what keeps this script-agnostic —
  // Cyrillic, Arabic, Japanese and Portuguese all pass, an emoji wall does not.
  if (prose.isNotEmpty) {
    var letters = 0;
    for (final r in prose.runes) {
      if (_isLetterOrDigit(r)) letters++;
    }
    final visible = prose.replaceAll(' ', '').runes.length;
    if (visible >= 8 && letters * 10 < visible * 4) {
      return const FeedReject(FeedDrop.symbolDominant);
    }
  }

  return const FeedKeep();
}

/// Letters and digits across every script — not just ASCII. A post in Japanese
/// or Arabic is not spam, and a filter that assumes A-Z would quietly delete
/// most of the world.
bool _isLetterOrDigit(int rune) {
  if (rune < 128) {
    return (rune >= 48 && rune <= 57) || // 0-9
        (rune >= 65 && rune <= 90) || // A-Z
        (rune >= 97 && rune <= 122); // a-z
  }
  // Above ASCII: treat anything outside the symbol/emoji planes as a letter.
  // Emoji live in 0x2190-0x2BFF (arrows/symbols), 0xFE00-0xFE0F (variation
  // selectors) and 0x1F000+ (pictographs); everything else is somebody's script.
  if (rune >= 0x1F000) return false;
  if (rune >= 0x2190 && rune <= 0x2BFF) return false;
  if (rune >= 0xFE00 && rune <= 0xFE0F) return false;
  if (rune >= 0x2600 && rune <= 0x27BF) return false;
  return true;
}

/// Normalized form used to spot the same text posted by different accounts:
/// case-folded, whitespace-collapsed, links and hashtags stripped (a bot ring
/// rotates the link, not the pitch).
String normalizeForDuplicate(String content) => content
    .toLowerCase()
    .replaceAll(_url, ' ')
    .replaceAll(_hashtag, ' ')
    .replaceAll(_whitespace, ' ')
    .trim();

// ── The stateful gate ───────────────────────────────────────────────────────

/// Bounded, self-expiring caches over the pure rules. One per firehose.
class FirehoseFilter {
  FirehoseFilter({
    this.maxPerMinute = 4,
    this.duplicateWindow = const Duration(minutes: 10),
    // Long enough for the profile REQ to be batched, sent, and answered by a
    // relay over a phone's connection. Too short and the strict rule silently
    // eats the feed — which is exactly what it did at 60s on a live network.
    this.pendingTtl = const Duration(minutes: 3),
    this.maxPending = 400,
    this.requireProfile = true,
  });

  /// One author posting faster than this is a bot or a bridge, not a person.
  final int maxPerMinute;
  final Duration duplicateWindow;

  /// How long a post waits for its author's profile before it is given up on.
  final Duration pendingTtl;
  final int maxPending;

  /// The strict rule. Off = the "moderate" gate (everything except noProfile).
  final bool requireProfile;

  static const int _maxDupes = 2000;
  static const int _maxAuthors = 1000;

  // normalized content hash -> (first author seen, when)
  final LinkedHashMap<String, ({String author, int atMs})> _seenText =
      LinkedHashMap();

  // pubkey -> recent post times (ms), newest last
  final LinkedHashMap<String, List<int>> _authorPosts = LinkedHashMap();

  // pubkey -> posts waiting for that author's kind-0
  final Map<String, List<({NostrEvent event, int atMs})>> _pending = {};
  int _pendingCount = 0;

  /// Drop counts by reason, for the telemetry line. "The feed looks empty" must
  /// always be answerable from the log rather than by guesswork.
  final Map<FeedDrop, int> drops = {};
  int kept = 0;
  int pendingNow = 0;

  /// [hasProfile] reads a CACHE. It must never fetch: calling a profile lookup
  /// that subscribes as a side effect, once per firehose event, is the "cosmetic
  /// value in a hot loop" that pegged a core (aurora/docs/performance.md §4.2).
  /// [trusted] is true for our own posts and for people we follow — they are not
  /// strangers and skip the gate entirely.
  FeedVerdict verdict(
    NostrEvent event, {
    required bool Function(String pubkey) hasProfile,
    required bool Function(String pubkey) trusted,
    required bool Function(String pubkey) muted,
    required int nowMs,
  }) {
    if (muted(event.pubkey)) return _reject(FeedDrop.muted);
    if (trusted(event.pubkey)) {
      kept++;
      return const FeedKeep();
    }

    final content = contentVerdict(event.content);
    if (content is FeedReject) return _reject(content.reason);

    if (_isFlooding(event.pubkey, nowMs)) return _reject(FeedDrop.flooding);
    if (_isDuplicate(event, nowMs)) return _reject(FeedDrop.duplicate);

    if (requireProfile && !hasProfile(event.pubkey)) {
      return const FeedPending();
    }

    kept++;
    return const FeedKeep();
  }

  FeedVerdict _reject(FeedDrop reason) {
    drops[reason] = (drops[reason] ?? 0) + 1;
    return FeedReject(reason);
  }

  bool _isFlooding(String pubkey, int nowMs) {
    final cutoff = nowMs - 60 * 1000;
    final times = _authorPosts.remove(pubkey) ?? <int>[];
    times.removeWhere((t) => t < cutoff);
    times.add(nowMs);
    _authorPosts[pubkey] = times; // re-insert = most-recently-used
    while (_authorPosts.length > _maxAuthors) {
      _authorPosts.remove(_authorPosts.keys.first);
    }
    return times.length > maxPerMinute;
  }

  bool _isDuplicate(NostrEvent event, int nowMs) {
    final key = normalizeForDuplicate(event.content);
    if (key.length < 12) return false; // "gm" is not a copy-paste ring
    final cutoff = nowMs - duplicateWindow.inMilliseconds;
    final prior = _seenText[key];
    if (prior != null && prior.atMs >= cutoff) {
      // The SAME author reposting their own words is not a bot ring — it is a
      // person repeating themselves, and the flood rule already covers that.
      if (prior.author != event.pubkey) return true;
      return false;
    }
    _seenText.remove(key);
    _seenText[key] = (author: event.pubkey, atMs: nowMs);
    while (_seenText.length > _maxDupes) {
      _seenText.remove(_seenText.keys.first);
    }
    return false;
  }

  /// Hold a post whose author has no profile yet.
  void hold(NostrEvent event, int nowMs) {
    final list = _pending.putIfAbsent(event.pubkey, () => []);
    list.add((event: event, atMs: nowMs));
    _pendingCount++;
    _expire(nowMs);
    pendingNow = _pendingCount;
  }

  /// The author's kind-0 arrived — everything of theirs that was waiting is now
  /// releasable, in the order it was held.
  List<NostrEvent> release(String pubkey, int nowMs) {
    final held = _pending.remove(pubkey);
    if (held == null || held.isEmpty) return const [];
    _pendingCount -= held.length;
    pendingNow = _pendingCount;
    final cutoff = nowMs - pendingTtl.inMilliseconds;
    final out = [
      for (final h in held)
        if (h.atMs >= cutoff) h.event,
    ];
    // The profile arrived too late for these: count them, or the pending queue
    // appears to shrink with nothing kept and nothing expired, and the numbers
    // stop adding up exactly when you need them to.
    expired += held.length - out.length;
    kept += out.length;
    return out;
  }

  /// Posts whose profile never came. They are not spam — we simply never learned
  /// who wrote them — so they are counted separately from the drops.
  int expired = 0;

  void _expire(int nowMs) {
    final cutoff = nowMs - pendingTtl.inMilliseconds;
    final emptyAuthors = <String>[];
    for (final e in _pending.entries) {
      final before = e.value.length;
      e.value.removeWhere((h) => h.atMs < cutoff);
      final gone = before - e.value.length;
      if (gone > 0) {
        _pendingCount -= gone;
        expired += gone;
      }
      if (e.value.isEmpty) emptyAuthors.add(e.key);
    }
    for (final k in emptyAuthors) {
      _pending.remove(k);
    }
    // Hard cap: a firehose of unknown authors must not grow memory without
    // bound. Oldest holders go first.
    while (_pendingCount > maxPending && _pending.isNotEmpty) {
      final k = _pending.keys.first;
      final list = _pending.remove(k)!;
      _pendingCount -= list.length;
      expired += list.length;
    }
    pendingNow = _pendingCount;
  }

  /// Counters for the telemetry line, reset on read.
  Map<String, int> drainStats() {
    final out = <String, int>{
      'kept': kept,
      'pending': _pendingCount,
      'expired': expired,
      for (final e in drops.entries) e.key.name: e.value,
    };
    kept = 0;
    expired = 0;
    drops.clear();
    return out;
  }
}
