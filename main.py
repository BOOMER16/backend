"""
VANTA//FLOW backend - Layer 2 (Fast Ingestion) + Layer 3 (Threat Intel) +
Layer 4 (Event Orchestrator) from the architecture doc, collapsed into one
Render-deployable FastAPI service for the SIH demo.

Run locally:   uvicorn main:app --reload --port 8000
Then run:      python synthetic_generator.py   (in a second terminal)
Then connect a WebSocket client to ws://localhost:8000/ws/stream

WebSocket message types broadcast on /ws/stream:
  telemetry       - one per packet, drives the Watch Desk entropy chart/feed
  threat_alert     - one per NEW incident (not per packet), full evidence
                     bundle for the Investigate screen
  incident_update  - sent whenever an incident's packet_count/status changes
  audit_event      - system/analyst events for the Overview audit log
  stats            - aggregate counters, broadcast on a ~2Hz timer, for the
                     Overview screen's summary figures
"""
import asyncio
import hashlib
import json
import struct
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from detection_engine import Tier1Triage, byte_histogram
from gemini_client import classify_anomaly
from incident_tracker import IncidentTracker
from stats_tracker import AuditLog, BufferDropDetector, LatencyTracker, MitreTally, RollingRateCounter

UDP_HOST = "0.0.0.0"
UDP_PORT = 9999
STATS_BROADCAST_INTERVAL_S = 0.5   # ~2Hz, matches the architecture doc's Layer 4 spec
INCIDENT_SWEEP_INTERVAL_S = 2.0


class ConnectionManager:
    def __init__(self):
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, message: dict):
        dead = []
        payload = json.dumps(message)
        for ws in self.active:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()
tier1 = Tier1Triage(window_size=1000)
incidents = IncidentTracker()
audit_log = AuditLog()
mitre_tally = MitreTally()
latency = LatencyTracker()
anomaly_rate_10m = RollingRateCounter(window_s=600)
buffer_drops = BufferDropDetector()

anomaly_queue: asyncio.Queue = asyncio.Queue()
stats = {"packets_seen": 0, "anomalies_flagged": 0, "started_at": time.time()}


class DiodeIngestProtocol(asyncio.DatagramProtocol):
    """
    Simulates the receiving side of a hardware data diode: this socket only
    ever reads. Nothing in this process ever sends a reply back to the
    sender -- there is no return path, by design (see Module 1 of the docs).

    Wire format: 8-byte big-endian sequence number, then payload content.
    The sequence number is stripped before any entropy/feature calculation
    so it never skews the math -- it exists purely for drop detection.
    """

    def datagram_received(self, data: bytes, addr):
        seq = None
        content = data
        if len(data) >= 8:
            seq = struct.unpack(">Q", data[:8])[0]
            content = data[8:]
        buffer_drops.observe(seq)

        t0 = time.perf_counter()
        features, is_anomaly, sigma_dev, attribution = tier1.process(content, seq=seq)
        latency.record(time.perf_counter() - t0)

        stats["packets_seen"] += 1

        asyncio.create_task(manager.broadcast({
            "type": "telemetry",
            "timestamp": features.timestamp,
            "length": features.length,
            "entropy": round(features.entropy, 3),
            "iat_us": round(features.iat_us, 1) if features.iat_us else None,
            "sigma_dev": round(sigma_dev, 2),
            "baseline_mean": round(tier1.baseline_entropy.mean, 3),
            "baseline_threshold": round(tier1.baseline_entropy.threshold, 3),
            "is_anomaly": is_anomaly,
            "packets_seen": stats["packets_seen"],
        }))

        if is_anomaly:
            stats["anomalies_flagged"] += 1
            anomaly_rate_10m.record(features.timestamp)
            incident, is_new = incidents.add_packet(features.entropy, sigma_dev, at=features.timestamp)

            asyncio.create_task(manager.broadcast({
                "type": "incident_update",
                "incident": incident.to_dict(),
            }))

            if is_new:
                source = f"{addr[0]}:{addr[1]}"
                sha256 = hashlib.sha256(content).hexdigest()
                anomaly_queue.put_nowait((incident.id, features, sigma_dev, attribution, content, source, sha256))


async def tier2_worker():
    """Consumes NEWLY OPENED incidents (not every anomalous packet -- see
    incident_tracker.py) and asks Gemini (or the mock fallback) for a
    structured forensic verdict, then broadcasts the full evidence bundle."""
    while True:
        incident_id, features, sigma_dev, attribution, content, source, sha256 = await anomaly_queue.get()
        verdict = await classify_anomaly(
            entropy=features.entropy,
            sigma_dev=sigma_dev,
            iat_us=features.iat_us,
            length=features.length,
            variance=features.window_variance,
        )
        incident = incidents.apply_verdict(incident_id, verdict)
        if incident is None:
            continue

        mitre_tally.record(verdict.mitre_technique, verdict.mitre_technique_name)
        audit_log.log(
            f"incident {incident.id} ({verdict.classification}) classified {verdict.severity}",
            event_type="incident",
        )

        histogram = byte_histogram(content)
        hex_preview = content[:64].hex()

        await manager.broadcast({
            "type": "threat_alert",
            "incident_id": incident.id,
            "timestamp": features.timestamp,
            "entropy": round(features.entropy, 3),
            "sigma_dev": round(sigma_dev, 2),
            "iat_us": round(features.iat_us, 1) if features.iat_us else None,
            "length": features.length,
            "source": source,
            "sha256": sha256,
            "hex_preview": hex_preview,
            "byte_histogram": histogram,
            "feature_attribution": attribution,
            "verdict": {
                "threat_detected": verdict.threat_detected,
                "confidence": verdict.confidence,
                "classification": verdict.classification,
                "mitre_technique": verdict.mitre_technique,
                "mitre_technique_name": verdict.mitre_technique_name,
                "severity": verdict.severity,
                "xai_explanation": verdict.xai_explanation,
                "source": verdict.source,
            },
        })
        await manager.broadcast({"type": "incident_update", "incident": incident.to_dict()})


async def stats_broadcaster():
    """~2Hz aggregate stats push, matching the architecture doc's Layer 4
    'streams packet telemetry at 2Hz' framing -- this drives the Overview
    screen's summary numbers."""
    while True:
        await asyncio.sleep(STATS_BROADCAST_INTERVAL_S)
        await manager.broadcast({
            "type": "stats",
            "packets_seen": stats["packets_seen"],
            "anomalies_flagged": stats["anomalies_flagged"],
            "anomalies_last_10m": anomaly_rate_10m.count(),
            "mean_latency_us": round(latency.mean_us, 2),
            "p99_latency_us": round(latency.p99_us, 2),
            "jitter_us": round(tier1.baseline_iat.std, 1),
            "buffer_drops": buffer_drops.drops,
            "baseline_entropy_mean": round(tier1.baseline_entropy.mean, 3),
            "baseline_entropy_std": round(tier1.baseline_entropy.std, 3),
            "mitre_techniques": mitre_tally.top(),
            "uptime_s": round(time.time() - stats["started_at"], 1),
        })


async def incident_sweeper():
    """Periodically resolves incidents that have gone quiet, and logs it."""
    while True:
        await asyncio.sleep(INCIDENT_SWEEP_INTERVAL_S)
        for incident in incidents.sweep_stale():
            audit_log.log(f"incident {incident.id} resolved (quiet {INCIDENT_SWEEP_INTERVAL_S:.0f}s+)", event_type="system")
            await manager.broadcast({"type": "incident_update", "incident": incident.to_dict()})
            await manager.broadcast({"type": "audit_event", "event": audit_log.recent(1)[0]})


@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        DiodeIngestProtocol, local_addr=(UDP_HOST, UDP_PORT)
    )
    tasks = [
        asyncio.create_task(tier2_worker()),
        asyncio.create_task(stats_broadcaster()),
        asyncio.create_task(incident_sweeper()),
    ]
    audit_log.log("VANTA//FLOW engine started", event_type="system")
    print(f"[VANTA//FLOW] Simulated diode listening on UDP {UDP_HOST}:{UDP_PORT}")
    yield
    for t in tasks:
        t.cancel()
    transport.close()


app = FastAPI(title="VANTA//FLOW", lifespan=lifespan)

# Loosen this to your actual Vercel domain before the live demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "uptime_s": round(time.time() - stats["started_at"], 1),
        **stats,
        "baseline_mean_entropy": round(tier1.baseline_entropy.mean, 3),
        "baseline_std": round(tier1.baseline_entropy.std, 3),
        "baseline_ready": tier1.baseline_entropy.ready,
        "buffer_drops": buffer_drops.drops,
        "gemini_mode": "live" if __import__("os").getenv("GEMINI_API_KEY") else "mock",
    }


@app.get("/incidents")
async def list_incidents():
    return {"incidents": incidents.list_all()}


@app.get("/audit-log")
async def get_audit_log():
    return {"entries": audit_log.recent(50)}


class IncidentActionRequest(BaseModel):
    action: str  # "quarantine" | "mark_false_positive"


@app.post("/incidents/{incident_id}/action")
async def incident_action(incident_id: str, req: IncidentActionRequest):
    incident = incidents.action(incident_id, req.action)
    if incident is None:
        return {"error": "incident not found"}, 404
    verb = "marked false positive" if req.action == "mark_false_positive" else "quarantined"
    entry = audit_log.log(f"incident {incident_id} {verb} by analyst", event_type="analyst")
    await manager.broadcast({"type": "incident_update", "incident": incident.to_dict()})
    await manager.broadcast({"type": "audit_event", "event": entry})
    return {"incident": incident.to_dict()}


@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect inbound client messages, but keep the socket alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
