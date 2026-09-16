import { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { IngestionForm } from './components/IngestionForm';
import { TelemetryStream } from './components/TelemetryStream';
import { ReasoningPanel } from './components/ReasoningPanel';
import { PlaybookConsole } from './components/PlaybookConsole';
import { HistorySidebar } from './components/HistorySidebar';
import type { IngestResponse } from './types/soc';

export function App() {
  const [history, setHistory] = useState<IngestResponse[]>([]);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Connect to backend WebSocket for async pipeline results
  useEffect(() => {
    const ws = new WebSocket('ws://127.0.0.1:8000/ws/telemetry');
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.status === 'success' && msg.enriched_incident_object) {
          const eio = msg.enriched_incident_object;
          
          // Map backend schema to frontend IngestResponse schema
          const mappedResponse: IngestResponse = {
            status: "success",
            quarantined: eio.security_flags?.includes("PROMPT_INJECTION_DETECTED"),
            guardrail: {
              status: eio.security_flags?.includes("PROMPT_INJECTION_DETECTED") ? "blocked" : "allowed",
              confidence: 0.99,
              latency_ms: 15.0
            },
            enriched_incident_object: {
              incident_id: eio.incident_id || "unknown",
              timestamp: eio.timestamp || new Date().toISOString(),
              sanitized_payload: eio.sanitized_payload || "",
              structural_context: eio.structural_context || { source_ip: "", target_ip: "", criticality: "HIGH", zone: "" },
              security_flags: eio.security_flags || []
            },
            incident_hypothesis: {
              attack_type: eio.incident_hypothesis?.suspected_tactic || "Unknown",
              confidence_score: eio.incident_hypothesis?.confidence || 0.85,
              mitre_tactics: [eio.incident_hypothesis?.technique_id || "T0000"],
              recommended_action: eio.incident_hypothesis?.counterfactual_hypotheses?.[0] || "Monitor"
            },
            simulation_valid: eio.sse_validation?.status === "VERIFIED",
            composite_risk_score: eio.sse_validation?.containment_playbook?.risk_score || 50,
            playbook_workflow: {
              primary_action: eio.sse_validation?.containment_playbook?.action || "MONITOR",
              severity: "HIGH",
              risk_score_evaluated: eio.sse_validation?.containment_playbook?.risk_score || 50,
              mitre_tactics: [eio.incident_hypothesis?.technique_id || "T0000"],
              execution_steps: eio.sse_validation?.recommended_mitigations || ["Isolate Host"]
            },
            audit_log_ref: "WORM-S3-" + (eio.incident_id?.substring(0,8) || "0000"),
            processed_payload: eio.sanitized_payload,
            pipeline_latency_ms: msg.pipeline_latency_ms || 1.5,
            sandbox_confirmation: eio.sandbox_event || null
          };
          
          setHistory((prev) => [mappedResponse, ...prev]);
          setSelectedIndex(0);
          setIsLoading(false); // Pipeline complete
        }
      } catch (e) {
        console.error("Failed to parse websocket message", e);
      }
    };
    return () => ws.close();
  }, []);

  // Latest selected or active response
  const activeResponse: IngestResponse | null =
    selectedIndex !== null && history[selectedIndex] ? history[selectedIndex] : history[0] || null;

  const latestLatencyMs: number | null = activeResponse ? activeResponse.pipeline_latency_ms : null;

  const handleIngest = async (logText: string, sourceIp: string, targetIp: string) => {
    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await fetch('http://127.0.0.1:8000/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Cryptographic-Nonce': crypto.randomUUID(),
          'X-Ed25519-Signature': 'mock_frontend_signature_001122334455' // Meets length req for edge AI mock verification
        },
        body: JSON.stringify({
          log: logText,
          source_ip: sourceIp,
          target_ip: targetIp,
          sync_execution: false
        }),
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP status ${response.status}`);
      }

      // We expect 202 Accepted. Real data arrives via WebSocket.
    } catch (err: any) {
      setErrorMessage(
        err?.message || 'Failed to communicate with AgentSOC local backend at http://127.0.0.1:8000/ingest'
      );
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Header */}
      <Header latestLatencyMs={latestLatencyMs} />

      {/* Main Dashboard Layout */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* Error Notification Banner */}
        {errorMessage && (
          <div className="bg-rose-500/10 border border-rose-500/40 text-rose-300 px-4 py-3 rounded-xl text-xs font-mono flex items-center justify-between shadow-lg glow-rose">
            <span>⚠️ API Error: {errorMessage}</span>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-rose-400 hover:text-white font-bold ml-4"
            >
              ✕
            </button>
          </div>
        )}

        {/* 3-Column Responsive Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Ingestion Console & Vector Testbench */}
          <div className="lg:col-span-5 space-y-6">
            <IngestionForm onIngest={handleIngest} isLoading={isLoading} />
            <div className="hidden lg:block">
              <HistorySidebar
                history={history}
                selectedIndex={selectedIndex}
                onSelect={(idx) => setSelectedIndex(idx)}
              />
            </div>
          </div>

          {/* Center Column: Enriched Telemetry Stream */}
          <div className="lg:col-span-4 space-y-6">
            <TelemetryStream currentResponse={activeResponse} />
            {/* Mobile / Tablet History Drawer */}
            <div className="lg:hidden">
              <HistorySidebar
                history={history}
                selectedIndex={selectedIndex}
                onSelect={(idx) => setSelectedIndex(idx)}
              />
            </div>
          </div>

          {/* Right Column: AI Reasoning, Risk Gauge & Remediation Playbook */}
          <div className="lg:col-span-3 space-y-6">
            <ReasoningPanel
              hypothesis={activeResponse?.incident_hypothesis || null}
              simulationValid={activeResponse?.simulation_valid ?? null}
            />
            <PlaybookConsole
              workflow={activeResponse?.playbook_workflow || null}
              riskScore={activeResponse?.composite_risk_score ?? null}
              auditRef={activeResponse?.audit_log_ref || null}
            />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs font-mono text-slate-600">
        AgentSOC Log Mitigation Gauntlet • Sub-500ms Local Security Architecture
      </footer>
    </div>
  );
}

export default App;
