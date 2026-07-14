/*
 * firehose_curator — a firehose is not a feed.
 *
 * Public relays produce far more than a phone can render or a person can read:
 * the engine was handing the wapp up to 150 events a second, the wapp could take
 * about 26, and so the feed was permanently chewing through a backlog while the
 * newest post on screen got older and older. Draining faster only moves the
 * bottleneck; the answer is to stop pouring.
 *
 * So everything that survives the quality gate (feed_quality.dart — which says
 * what is NOT spam) arrives here, which says what is WORTH SHOWING FIRST. It is a
 * bounded buffer of candidates, and on a timer it emits the best few, newest-first
 * among equals.
 *
 * Every signal is one we already hold locally. No extra network call, no
 * follower-count service (there isn't one in NOSTR anyway) — just what the device
 * has already learned:
 *
 *   * engagement — likes and replies the hub has already tallied;
 *   * pictures — a post with an image is what a feed is for;
 *   * a real profile — an author with a name and a picture is a person, not a bot;
 *   * a face we keep seeing — an author whose posts we have already accepted;
 *   * freshness — of two equally good posts, the newer one wins.
 *
 * People the user FOLLOWS never come through here. They are not candidates to be
 * ranked against strangers; they are the point.
 */
import '../../util/nostr_event.dart';

/// What the hub knows about a candidate, passed in so the curator stays pure and
/// testable — it never reaches into the hub's caches itself.
typedef CandidateSignals = ({
  int likes,
  int replies,
  bool hasMedia,
  bool authorHasProfile,
  int authorSeenBefore,
});

class ScoredPost {
  final NostrEvent event;
  final double score;
  final int atMs;
  const ScoredPost(this.event, this.score, this.atMs);
}

class FirehoseCurator {
  FirehoseCurator({
    this.maxCandidates = 300,
    this.perMinute = 12,
    this.firstBurst = 30,
  });

  /// How many posts we hold, ranked, waiting for their turn. Bounded: a firehose
  /// never stops, and the point is to keep the BEST few, not all of them.
  final int maxCandidates;

  /// How many we hand the feed per minute once it is warm. A person reads a
  /// handful of posts a minute; a phone renders a handful without stuttering.
  final int perMinute;

  /// The first handful, so an opened tab fills at once instead of trickling.
  final int firstBurst;

  final List<ScoredPost> _candidates = [];
  bool _warm = false;

  int get pending => _candidates.length;

  /// Rank a post and hold it. Returns nothing — delivery happens on [take].
  void offer(NostrEvent event, CandidateSignals s, int nowMs) {
    final score = scoreOf(event, s, nowMs);
    _candidates.add(ScoredPost(event, score, nowMs));
    // Keep the best. When the buffer is full the WORST candidate goes, not the
    // oldest: a firehose's problem is never a shortage of posts.
    if (_candidates.length > maxCandidates) {
      _candidates.sort((a, b) => a.score.compareTo(b.score));
      _candidates.removeRange(0, _candidates.length - maxCandidates);
    }
  }

  /// The best posts to show now, newest-first among equals. Call on a timer.
  List<NostrEvent> take(int nowMs) {
    if (_candidates.isEmpty) return const [];
    final want = _warm ? _perTick() : firstBurst;
    _warm = true;

    _candidates.sort((a, b) {
      final byScore = b.score.compareTo(a.score);
      if (byScore != 0) return byScore;
      return b.event.createdAt.compareTo(a.event.createdAt);
    });

    final n = want < _candidates.length ? want : _candidates.length;
    final out = _candidates.sublist(0, n);
    _candidates.removeRange(0, n);
    // Newest first is what a feed means, whatever order they were ranked in.
    out.sort((a, b) => b.event.createdAt.compareTo(a.event.createdAt));
    return [for (final c in out) c.event];
  }

  /// Emit is called every [tickSeconds]; spread the per-minute allowance across
  /// the ticks so the feed advances steadily rather than in lumps.
  static const int tickSeconds = 10;
  int _perTick() {
    final n = (perMinute * tickSeconds) ~/ 60;
    return n < 1 ? 1 : n;
  }

  /// The ranking itself. Deliberately simple and explainable: if a post is hidden
  /// (or promoted) the reason has to be sayable in one sentence.
  double scoreOf(NostrEvent event, CandidateSignals s, int nowMs) {
    var score = 0.0;

    // Somebody else already thought it was worth something. The strongest signal
    // we have, and the cheapest — it costs the network nothing to tell us.
    score += s.likes * 2.0;
    score += s.replies * 3.0; // a reply is a bigger commitment than a like

    // A feed with pictures in it is a feed people look at.
    if (s.hasMedia) score += 4.0;

    // A name and a picture is the cheapest evidence of a person rather than a
    // script. It is not proof — it is a prior.
    if (s.authorHasProfile) score += 3.0;

    // An author we keep accepting is one this device has already vouched for,
    // repeatedly. Capped, so a prolific account cannot buy the whole feed.
    score += (s.authorSeenBefore > 5 ? 5 : s.authorSeenBefore) * 0.5;

    // Freshness. A great post from an hour ago still loses to a good one from a
    // minute ago — this is a feed, not an archive.
    final ageMin = ((nowMs ~/ 1000) - event.createdAt) / 60.0;
    if (ageMin <= 2) {
      score += 4.0;
    } else if (ageMin <= 10) {
      score += 2.0;
    } else if (ageMin > 60) {
      score -= 3.0;
    }

    // Something to actually read. Not a rule about length — a floor under the
    // one-word posts that survive the spam gate but make a feed feel empty.
    final len = event.content.trim().length;
    if (len >= 80) score += 1.0;
    if (len < 15) score -= 1.0;

    return score;
  }
}
