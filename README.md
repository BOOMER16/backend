# VANTA//FLOW Backend

Tier 1 (stateless entropy/IAT/length triage) + Tier 2 (Gemini 2.5 Flash
forensic classifier, called once per incident) + incident grouping + audit
log + WebSocket event orchestrator, in one FastAPI service.

## What's real here (not mocked)

- Shannon entropy, sliding-window variance, and independent rolling 3-sigma
  baselines for entropy / inter-arrival time / packet length
- Deterministic feature attribution ("why this was flagged") computed from
  actual per-signal deviation magnitude, not guessed by the LLM
- Incident grouping: temporally-close anomalous packets fold into one
  incident, and Tier 2 is only called ONCE per incident (real cost saving,
  not just UI tidiness)
- Per-packet Tier 1 processing latency (mean + p99), measured with
  `time.perf_counter()` around the actual detection call
- UDP sequence-number framing + genuine drop detection (there's no ACK/
  retransmit on a diode, so a sequence gap is the only honest way to know
  a datagram was lost)
- 256-bin byte histogram, 64-byte hex preview, and SHA-256 of the actual
  flagged payload
- In-memory audit log covering system, incident, and analyst-action events
- MITRE ATT&CK technique tally across confirmed verdicts

## WebSocket message types (`/ws/stream`)

| type | sent | purpose |
|---|---|---|
| `telemetry` | every packet | Watch Desk entropy chart + live feed |
| `incident_update` | on incident create/change/resolve | Investigate incident list |
| `threat_alert` | once per NEW incident | full evidence bundle (histogram, hex, attribution, verdict) |
| `audit_event` | on any audit log entry | Overview audit log |
| `stats` | ~2Hz | aggregate counters for Overview (latency, drops, MITRE tally, jitter) |

## REST endpoints

- `GET /health` — status + core counters
- `GET /incidents` — full incident list (for page load, before any WS events arrive)
- `GET /audit-log` — recent audit entries
- `POST /incidents/{id}/action` — body `{"action": "quarantine" | "mark_false_positive"}`

## Run locally

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Terminal 1
uvicorn main:app --reload --port 8000

# Terminal 2 - simulated diode traffic
python synthetic_generator.py --attack-every 15 --burst-size 12
```

Open `fallback-dashboard/index.html` in a browser (or your Next.js app) and
connect to `ws://localhost:8000/ws/stream`.

Check `http://localhost:8000/health` any time for live stats.

## Gemini live mode

By default `GEMINI_API_KEY` is unset and Tier 2 runs in **mock mode** — a
local classifier that returns fully schema-correct verdicts instantly, no
network required. This is deliberate: it means your stage demo cannot be
broken by venue wifi or a rate limit.

To use the real Gemini API: copy `.env.example` to `.env`, add your key,
and `export $(cat .env | xargs)` before starting uvicorn (or set the env
var directly in your shell / Render dashboard). `/health` reports which
mode is active (`gemini_mode: "live"` or `"mock"`).

## Deploy to Render

1. Push this `backend/` folder to GitHub (Antigravity can do this for you).
2. Render → New → Web Service → connect the repo, root directory `backend/`.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add `GEMINI_API_KEY` as an environment variable only if you want live mode.
6. Once deployed, your WebSocket URL is `wss://<your-app>.onrender.com/ws/stream`.

**Important:** Render's free tier does not expose raw UDP ports to the public
internet — only your web service's HTTP(S)/WSS port is reachable. That's fine
for this demo because the "diode" (`synthetic_generator.py`) and the FastAPI
service are meant to run on the *same* trusted machine/process (exactly like
a real diode-adjacent ingestion node). For the live demo, either:
  - run `synthetic_generator.py` locally against your **local** uvicorn
    instance and point the frontend at `ws://localhost:8000/ws/stream`, or
  - run both `uvicorn` and `synthetic_generator.py` together inside the
    Render instance (e.g. a small supervisor script / Procfile with two
    processes) so the UDP hop never has to leave the box.

## Tuning the demo

`synthetic_generator.py --attack-every N --burst-size M --drop-rate D`
controls the demo pacing:
  - Lower `--attack-every` for a punchier live demo (e.g. `8`) so judges see
    an alert within the first minute.
  - **Keep `--attack-every` above 3 seconds** if you want each burst to show
    up as a *separate* incident on the Investigate screen — bursts spaced
    closer than that fold into one continuous incident (see
    `GROUP_WINDOW_S` in `incident_tracker.py`). That's correct behavior,
    not a bug, but it's worth knowing before you're live on stage wondering
    why you only see one incident.
  - `--drop-rate 0.05` (5%) is a good way to make the "buffer drops" stat on
    the dashboard visibly move during the demo instead of sitting at 0.
