"""
AgentSOC - Production FastAPI Ingestion Endpoint (main.py)
IEEE Publication Grade Asynchronous Log Mitigation Gauntlet with Single-Digit Millisecond Ingestion SLA.
Stitches together Perception, Guardrails, Narrative Counterfactual Engine, and Structural Simulation.
"""

import time
import uuid
import datetime
import logging
import json
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Import all layers of the AgentSOC Pipeline
from .perception import PerceptionLayer
from .guardrails import SLMGuardrail
from .agents.swarm import MultiAgentEpistemicDebate
from .sse_rsem import StructuralSimulationEngine

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AgentSOC Security Telemetry Ingestion Pipeline",
    description="Edge-AI Multi-Layer Agentic Framework for Security Operations (IEEE Grade Implementation)",
    version="2.0-GAUNTLET"
)

# Layer 0: zk-Telemetry Cryptographic Attestation
from .attestation import CryptographicAttestationMiddleware
app.add_middleware(CryptographicAttestationMiddleware)

# Enable CORS for Edge & Dashboard Clients
# IMPORTANT: Added AFTER CryptographicAttestationMiddleware so it is outermost and handles OPTIONS preflights
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import Real-Time WebSocket Telemetry Engine
from .telemetry import WebSocketManager

# ---------------------------------------------------------
# Global Pipeline Instantiation
# ---------------------------------------------------------
ws_manager = WebSocketManager()

# Layer 1: Deterministic Perception & State
perception_layer = PerceptionLayer()
# Layer 2: DeBERTa-v3 Semantic Guardrails
guardrail_layer = SLMGuardrail()
# Layer 3: Multi-Agent Epistemic Debate (MAED)
maed_layer = MultiAgentEpistemicDebate()
# Layer 4: Mathematical Graph Validation & Risk Scoring
sse_layer = StructuralSimulationEngine()

class RawSecurityLogPayload(BaseModel):
    log: str = Field(..., description="Raw security log text or payload entry")
    source_ip: Optional[str] = Field("10.0.0.1", description="Source IP address or asset identifier")
    target_ip: Optional[str] = Field("10.0.0.5", description="Target destination IP address or server asset")
    sync_execution: Optional[bool] = Field(False, description="Set False for single-digit ms 202 Accepted background mode")

@app.get("/")
async def root():
    return {
        "status": "ONLINE",
        "system": "AgentSOC Security Telemetry Ingestion Engine",
        "ingest_endpoint": "POST /ingest",
        "websocket_endpoint": "WS /ws/telemetry"
    }

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"status": "acknowledged", "echo": data})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

async def _process_alert_background(raw_log: str, source_ip: str, target_ip: str):
    """
    Non-blocking Background Task Runner executing the entire end-to-end AgentSOC pipeline.
    """
    try:
        # 1. Perception Layer: Generate the base Enriched Incident Object (EIO)
        # Note: We extract the raw dictionary for the next phases
        perception_result = await perception_layer.process_event(raw_log, source_ip, target_ip)
        eio = perception_result.get("enriched_incident_object")
        
        if not eio:
            logger.warning("[Pipeline] Perception Layer dropped the event. Halting pipeline.")
            return

        # 2. Guardrail Layer: Sanitize malicious overrides and prompt injections
        eio = await guardrail_layer.sanitize_eio(eio)
        
        # 3. MAED Layer: Generate Multi-Agent Consensus Hypotheses
        eio = await maed_layer.generate_hypotheses(eio)

        # 4. SSE Layer: Validate against Graph Database & Calculate RSEM Risk Score
        # (Mapped to evaluate_incident which handles verify_and_score logic)
        active_alerts = perception_layer.get_sliding_window_count()
        final_eio = await sse_layer.evaluate_incident(eio, active_alerts_in_window=active_alerts)
        
        # Merge the final processed EIO back into a payload for the WebSocket
        final_result = {
            "status": "success",
            "enriched_incident_object": final_eio,
            "pipeline_latency_ms": perception_result.get("pipeline_latency_ms", 0) # Base latency
        }
        
        # Actionable Rehydration: Scan and replace PII tokens with raw values for human analysts
        final_result = await perception_layer.redactor.rehydrate_playbook(final_result)
        
        # Broadcast completed analysis to the dashboard
        await ws_manager.broadcast(final_result)
        
        # 5. Terminal Presentation Logging for Demonstrations
        validation = final_eio.get("sse_validation", {})
        playbook = validation.get("containment_playbook", {})
        
        logger.info("\n" + "="*60)
        logger.info(f"🛡️  AGENT-SOC PIPELINE COMPLETED | ID: {final_eio.get('incident_id')}")
        logger.info(f"   Topological Verification : {validation.get('status')} ({validation.get('reason')})")
        logger.info(f"   Final Risk Score         : {playbook.get('risk_score', 'N/A')}")
        logger.info(f"   Recommended Playbook     : {playbook.get('action', 'NONE')} [{playbook.get('mode', 'N/A')}]")
        logger.info("="*60 + "\n")

    except Exception as e:
        logger.error(f"[Pipeline] Unhandled background processing failure: {e}", exc_info=True)

@app.post("/ingest")
async def ingest_security_log(payload: RawSecurityLogPayload, background_tasks: BackgroundTasks):
    """
    High-Speed Ingestion Endpoint.
    Offloads execution to a background thread to maintain the single-digit millisecond SLA.
    Returns HTTP 202 Accepted instantly.
    """
    start_time = time.perf_counter()
    incident_id = str(uuid.uuid4())
    queued_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Async Background Offloading Mode (Single-Digit Millisecond SLA)
    if not payload.sync_execution:
        background_tasks.add_task(
            _process_alert_background,
            payload.log,
            payload.source_ip,
            payload.target_ip
        )
        ingest_latency_ms = (time.perf_counter() - start_time) * 1000

        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "status": "ACCEPTED",
                "incident_id": incident_id,
                "queued_at": queued_at,
                "ingest_latency_ms": round(ingest_latency_ms, 3),
                "execution_mode": "BACKGROUND_PIPELINE"
            }
        )

    # Inline Synchronous Execution Mode (for direct debugging)
    # WARNING: This bypasses the async background SLA
    await _process_alert_background(payload.log, payload.source_ip, payload.target_ip)
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "SYNC_PROCESSED"})
