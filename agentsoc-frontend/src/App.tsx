import { useState } from 'react';
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
        },
        body: JSON.stringify({
          log: logText,
          source_ip: sourceIp,
          target_ip: targetIp,
        }),
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP status ${response.status}`);
      }

      const data: IngestResponse = await response.json();

      // Prepend to history array and select the latest
      setHistory((prev) => [data, ...prev]);
      setSelectedIndex(0);
    } catch (err: any) {
      setErrorMessage(
        err?.message || 'Failed to communicate with AgentSOC local backend at http://127.0.0.1:8000/ingest'
      );
    } finally {
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
