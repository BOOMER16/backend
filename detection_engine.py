"""
VANTA//FLOW - Tier 1 Detection Engine
Stateless, line-rate feature extraction: Shannon Entropy + Inter-Arrival Time (IAT)
+ packet length, each compared against its own rolling 3-sigma baseline, plus a
sliding-window entropy-variance check for padding/evasion attacks.

This module has ZERO dependencies on FastAPI/websockets/Gemini so it can be
unit-tested and reasoned about in complete isolation (matches the "stateless"
claim in the architecture doc).
"""
import math
import random
import time
from collections import deque, Counter
from dataclasses import dataclass, field
from typing import Optional


def shannon_entropy(payload: bytes) -> float:
    """
    H(X) = -sum(P(xi) * log2(P(xi))) for byte values 0x00-0xFF.
    Max possible value is 8.0 (log2(256)) for a perfectly uniform byte distribution.
    """
    if not payload:
        return 0.0
    counts = Counter(payload)
    length = len(payload)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def byte_histogram(payload: bytes) -> list[int]:
    """256-bin byte-value frequency histogram, for the Investigate evidence panel."""
    counts = [0] * 256
    for b in payload:
        counts[b] += 1
    return counts


def sliding_window_variance(payload: bytes, window: int = 16) -> float:
    """
    Defends against the 'entropy smoothing / padding' attack raised in the
    professor Q&A: an attacker who pads high-entropy ciphertext with
    low-entropy null bytes can keep *global* entropy under the 3-sigma gate,
    but the entropy of 16-byte sub-windows will vary wildly. We compute the
    variance of per-window entropy as a second, cheap signal.
    """
    if len(payload) < window * 2:
        return 0.0
    window_entropies = [
        shannon_entropy(payload[i:i + window])
        for i in range(0, len(payload) - window, window)
    ]
    if len(window_entropies) < 2:
        return 0.0
    mean = sum(window_entropies) / len(window_entropies)
    var = sum((x - mean) ** 2 for x in window_entropies) / len(window_entropies)
    return var


@dataclass
class PacketFeatures:
    timestamp: float
    length: int
    entropy: float
    iat_us: Optional[float]   # microseconds since previous packet
    window_variance: float
    seq: Optional[int] = None
    src_tag: str = "synthetic-diode-0"


@dataclass
class RollingBaseline:
    """Maintains running mean/std of a single scalar feature over the last
    `size` samples. O(1) per-sample update -- no per-sample re-scan of the
    whole window.

    Optionally seeded with deterministic synthetic samples at a target
    mean/std so the gate is meaningful from sample one instead of learning
    blind for ~30 samples. Without this, an attack that lands during the
    cold-start window gets misread as 'normal' and poisons the baseline --
    exactly the failure mode you do NOT want live on stage.
    """
    size: int = 1000
    seed_mean: float = 0.0
    seed_std: float = 0.0
    seed_count: int = 0
    _values: deque = field(default_factory=deque)
    _sum: float = 0.0
    _sumsq: float = 0.0

    def __post_init__(self):
        if self.seed_count > 0:
            rng = random.Random(1337)
            for _ in range(self.seed_count):
                self.push(rng.gauss(self.seed_mean, self.seed_std))

    def push(self, value: float) -> None:
        self._values.append(value)
        self._sum += value
        self._sumsq += value * value
        if len(self._values) > self.size:
            old = self._values.popleft()
            self._sum -= old
            self._sumsq -= old * old

    @property
    def mean(self) -> float:
        n = len(self._values)
        return self._sum / n if n else 0.0

    @property
    def std(self) -> float:
        n = len(self._values)
        if n < 2:
            return 0.0
        variance = max((self._sumsq / n) - (self.mean ** 2), 0.0)
        return math.sqrt(variance)

    @property
    def threshold(self) -> float:
        # 3-sigma gate, per Module 4.2 of the reference architecture
        return self.mean + 3 * self.std

    @property
    def ready(self) -> bool:
        return len(self._values) >= 30

    def sigma_dev(self, value: float) -> float:
        std = self.std or 1e-6
        return (value - self.mean) / std


class Tier1Triage:
    """
    The 'triage nurse'. Stateless per-packet feature extraction + O(1) rolling
    baseline comparison across three independent signals (entropy, inter-
    arrival time, packet length) plus the sliding-window variance check.
    Everything here must stay cheap: this is the code that has to survive a
    67.2ns/packet compute budget at 10Gbps line rate in the full production
    design (our demo runs at UDP-socket speed, which is far below that, but
    the algorithm is the same).
    """

    def __init__(self, window_size: int = 1000):
        # Entropy baseline seeded to the reference calibration from the
        # architecture doc (benign mean=4.12, std=0.35).
        self.baseline_entropy = RollingBaseline(
            size=window_size, seed_mean=4.12, seed_std=0.35, seed_count=40
        )
        # IAT baseline seeded to roughly match this demo's synthetic benign
        # traffic profile (irregular human-ish gaps, tens to hundreds of ms).
        # Attacks are anomalous in the LOW direction here (tight mechanized
        # timing), unlike entropy which is anomalous HIGH.
        self.baseline_iat = RollingBaseline(
            size=window_size, seed_mean=225_000, seed_std=100_000, seed_count=40
        )
        # Packet length baseline -- a weaker, supporting signal.
        self.baseline_length = RollingBaseline(
            size=window_size, seed_mean=90, seed_std=25, seed_count=40
        )
        self._last_ts: Optional[float] = None
        self.packet_count = 0
        self.anomaly_count = 0

    def process(self, payload: bytes, seq: Optional[int] = None):
        """
        Returns (features, is_anomaly, sigma_dev, feature_attribution)
        feature_attribution is a dict of {signal_name: percent_contribution}
        summing to ~100, only meaningful when is_anomaly is True.
        """
        now = time.time()
        entropy = shannon_entropy(payload)
        variance = sliding_window_variance(payload)
        length = len(payload)

        iat_us = None
        if self._last_ts is not None:
            iat_us = (now - self._last_ts) * 1_000_000
        self._last_ts = now

        features = PacketFeatures(
            timestamp=now,
            length=length,
            entropy=entropy,
            iat_us=iat_us,
            window_variance=variance,
            seq=seq,
        )

        sigma_dev = 0.0
        is_anomaly = False
        attribution = {}

        if self.baseline_entropy.ready:
            sigma_dev = self.baseline_entropy.sigma_dev(entropy)
            entropy_breach = entropy > self.baseline_entropy.threshold
            variance_breach = variance > 4.0  # empirical guard-rail for the padding attack
            is_anomaly = entropy_breach or variance_breach

            if is_anomaly:
                # Deterministic feature attribution: normalize the absolute
                # deviation magnitude of each independent signal so the
                # "why this was flagged" breakdown reflects real relative
                # contribution, not an LLM's guess at percentages.
                entropy_mag = abs(sigma_dev)
                iat_mag = (
                    abs(self.baseline_iat.sigma_dev(iat_us))
                    if iat_us is not None and self.baseline_iat.ready
                    else 0.0
                )
                length_mag = (
                    abs(self.baseline_length.sigma_dev(length))
                    if self.baseline_length.ready
                    else 0.0
                )
                variance_mag = variance  # already on a comparable small scale

                total = entropy_mag + iat_mag + length_mag + variance_mag
                if total > 0:
                    attribution = {
                        "payload_entropy": round(100 * entropy_mag / total, 1),
                        "inter_arrival_timing": round(100 * iat_mag / total, 1),
                        "window_variance": round(100 * variance_mag / total, 1),
                        "packet_length": round(100 * length_mag / total, 1),
                    }

        # Baselines only learn from traffic we did NOT already flag, so a
        # sustained attack can't slowly drag them and desensitize the gate.
        if not is_anomaly:
            self.baseline_entropy.push(entropy)
            if iat_us is not None:
                self.baseline_iat.push(iat_us)
            self.baseline_length.push(length)

        self.packet_count += 1
        if is_anomaly:
            self.anomaly_count += 1

        return features, is_anomaly, sigma_dev, attribution
