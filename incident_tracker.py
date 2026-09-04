"""
VANTA//FLOW - Incident grouping.

The Investigate/Overview screens ask for named, multi-packet "incidents"
(e.g. "Malleable C2 beacon - 6 packets - ACTIVE"), but Tier 1 flags
individual packets. This module groups temporally-close anomalous packets
into one incident, and -- as a real side benefit, not just UI plumbing --
means Tier 2 (Gemini) is only invoked ONCE per incident (on the first
packet), not once per anomalous packet in a burst. A 6-packet C2 beacon
burst becomes 1 API call, not 6. That's a genuine cost/latency argument
you can make to the judges, not just a cosmetic grouping.
"""
import itertools
import time
from dataclasses import dataclass, field
from typing import Optional

# Packets land in the same incident if they arrive within this many seconds
# of the last packet already in it. Tuned to your synthetic_generator's
# default burst spacing (packets a few ms apart, well under this).
GROUP_WINDOW_S = 3.0

# An ACTIVE incident with no new packets for this long is swept to RESOLVED.
RESOLVE_AFTER_S = 12.0

_id_counter = itertools.count(88214)  # cosmetic starting point, matches the mock's INC-88xxx style


@dataclass
class Incident:
    id: str
    first_detected: float
    last_seen: float
    packet_count: int = 1
    status: str = "PENDING"      # PENDING -> ACTIVE (has a verdict) -> RESOLVED
    classification: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    mitre_technique: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    xai_explanation: Optional[str] = None
    verdict_source: Optional[str] = None
    representative_entropy: float = 0.0
    representative_sigma: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "first_detected": self.first_detected,
            "last_seen": self.last_seen,
            "packet_count": self.packet_count,
            "status": self.status,
            "classification": self.classification or "Analyzing…",
            "severity": self.severity or "PENDING",
            "confidence": self.confidence,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_name": self.mitre_technique_name,
            "xai_explanation": self.xai_explanation,
            "verdict_source": self.verdict_source,
            "entropy": round(self.representative_entropy, 3),
            "sigma_dev": round(self.representative_sigma, 2),
        }


class IncidentTracker:
    def __init__(self):
        self._open: dict[str, Incident] = {}   # id -> Incident, only PENDING/ACTIVE
        self._all: dict[str, Incident] = {}     # id -> Incident, everything (for GET /incidents)

    def add_packet(self, entropy: float, sigma_dev: float, at: Optional[float] = None):
        """
        Returns (incident, is_new). is_new tells the caller whether to invoke
        Tier 2 classification (only on the first packet of a new incident).
        """
        now = at if at is not None else time.time()

        # Try to fold into the most recently active open incident.
        for incident in self._open.values():
            if now - incident.last_seen <= GROUP_WINDOW_S:
                incident.packet_count += 1
                incident.last_seen = now
                # Track the strongest deviation seen so far as the incident's
                # representative evidence numbers.
                if abs(sigma_dev) > abs(incident.representative_sigma):
                    incident.representative_sigma = sigma_dev
                    incident.representative_entropy = entropy
                return incident, False

        incident_id = f"INC-{next(_id_counter)}"
        incident = Incident(
            id=incident_id,
            first_detected=now,
            last_seen=now,
            representative_entropy=entropy,
            representative_sigma=sigma_dev,
        )
        self._open[incident_id] = incident
        self._all[incident_id] = incident
        return incident, True

    def apply_verdict(self, incident_id: str, verdict) -> Optional[Incident]:
        incident = self._all.get(incident_id)
        if incident is None:
            return None
        incident.status = "ACTIVE"
        incident.classification = verdict.classification
        incident.severity = verdict.severity
        incident.confidence = verdict.confidence
        incident.mitre_technique = verdict.mitre_technique
        incident.mitre_technique_name = verdict.mitre_technique_name
        incident.xai_explanation = verdict.xai_explanation
        incident.verdict_source = verdict.source
        return incident

    def sweep_stale(self, at: Optional[float] = None) -> list[Incident]:
        """Move quiet ACTIVE incidents to RESOLVED. Returns the list of
        incidents that just transitioned, so the caller can log/broadcast."""
        now = at if at is not None else time.time()
        resolved = []
        for incident_id in list(self._open.keys()):
            incident = self._open[incident_id]
            if incident.status == "ACTIVE" and now - incident.last_seen > RESOLVE_AFTER_S:
                incident.status = "RESOLVED"
                resolved.append(incident)
                del self._open[incident_id]
        return resolved

    def action(self, incident_id: str, action: str) -> Optional[Incident]:
        """Analyst action: quarantine or mark_false_positive. Both resolve
        the incident; false-positive additionally tags it so it's visually
        distinct from a genuine confirmed-and-handled threat."""
        incident = self._all.get(incident_id)
        if incident is None:
            return None
        if action == "mark_false_positive":
            incident.status = "FALSE_POSITIVE"
        else:
            incident.status = "QUARANTINED"
        self._open.pop(incident_id, None)
        return incident

    def list_all(self, limit: int = 50) -> list[dict]:
        incidents = sorted(self._all.values(), key=lambda i: i.last_seen, reverse=True)
        return [i.to_dict() for i in incidents[:limit]]

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._all.get(incident_id)
