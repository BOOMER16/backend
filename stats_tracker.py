"""
VANTA//FLOW - Cross-cutting stats trackers used by the Overview screen and
the health/stats endpoints. Kept separate from the detection engine so the
detection math stays provably stateless/isolated for the pitch defense.
"""
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Optional


class LatencyTracker:
    """Rolling Tier-1 processing latency, for 'mean detection latency' and
    p99 on the Overview screen. Measured with time.perf_counter() around the
    actual Tier1Triage.process() call -- this is real wall-clock cost, not
    a placeholder number."""

    def __init__(self, maxlen: int = 2000):
        self._samples: deque = deque(maxlen=maxlen)

    def record(self, seconds: float) -> None:
        self._samples.append(seconds * 1_000_000)  # store as microseconds

    @property
    def mean_us(self) -> float:
        if not self._samples:
            return 0.0
        return sum(self._samples) / len(self._samples)

    @property
    def p99_us(self) -> float:
        if not self._samples:
            return 0.0
        ordered = sorted(self._samples)
        idx = min(int(len(ordered) * 0.99), len(ordered) - 1)
        return ordered[idx]


class RollingRateCounter:
    """Counts timestamped events falling within the last `window_s` seconds.
    Used for 'anomalies in the last 10 minutes' style deltas."""

    def __init__(self, window_s: float):
        self.window_s = window_s
        self._events: deque = deque()

    def record(self, at: float = None) -> None:
        self._events.append(at if at is not None else time.time())
        self._prune()

    def count(self) -> int:
        self._prune()
        return len(self._events)

    def _prune(self) -> None:
        cutoff = time.time() - self.window_s
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


class BufferDropDetector:
    """Detects gaps in the monotonically increasing sequence number that
    synthetic_generator.py stamps on every packet. A real dropped UDP
    datagram on a diode is invisible any other way -- there's no
    retransmit, no ACK, nothing -- so sequence-gap counting is the only
    honest way to report this number."""

    def __init__(self):
        self._expected: Optional[int] = None
        self.drops = 0
        self.reordered = 0

    def observe(self, seq: Optional[int]) -> None:
        if seq is None:
            return
        if self._expected is None:
            self._expected = seq + 1
            return
        if seq >= self._expected:
            self.drops += seq - self._expected
            self._expected = seq + 1
        else:
            # Arrived out of order / behind what we already advanced past.
            self.reordered += 1


@dataclass
class AuditLog:
    """Simple in-memory, append-only event log for the Overview screen.
    Not persisted -- fine for a demo process lifetime; swap for a real
    datastore before this becomes a production service."""

    max_entries: int = 200
    _entries: list = field(default_factory=list)

    def log(self, message: str, event_type: str = "system") -> dict:
        entry = {
            "timestamp": time.time(),
            "message": message,
            "event_type": event_type,  # system | incident | analyst
        }
        self._entries.append(entry)
        if len(self._entries) > self.max_entries:
            self._entries.pop(0)
        return entry

    def recent(self, n: int = 25) -> list:
        return list(reversed(self._entries[-n:]))


class MitreTally:
    """Counts confirmed verdicts by MITRE ATT&CK technique, for the
    Overview 'Techniques observed' panel."""

    def __init__(self):
        self._counts: Counter = Counter()
        self._names: dict = {}

    def record(self, technique_id: str, technique_name: str) -> None:
        self._counts[technique_id] += 1
        self._names[technique_id] = technique_name

    def top(self, n: int = 8) -> list[dict]:
        return [
            {"technique": tid, "name": self._names.get(tid, ""), "count": count}
            for tid, count in self._counts.most_common(n)
        ]
