import React from 'react';
import { History, ShieldAlert, ShieldCheck, Clock } from 'lucide-react';
import type { IngestResponse } from '../types/soc';

interface HistorySidebarProps {
  history: IngestResponse[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
}

export const HistorySidebar: React.FC<HistorySidebarProps> = ({ history, selectedIndex, onSelect }) => {
  return (
    <div className="cyber-glass-card rounded-2xl p-4 border border-slate-800/80 shadow-2xl flex flex-col space-y-3 h-full">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
        <div className="flex items-center space-x-2">
          <History className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
            Incident Stream History
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
          {history.length} Events
        </span>
      </div>

      {history.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center p-4">
          <Clock className="w-6 h-6 text-slate-700 mb-2" />
          <p className="text-xs text-slate-600 font-mono">No historical telemetry recorded in this session yet.</p>
        </div>
      ) : (
        <div className="space-y-2 overflow-y-auto max-h-[500px] pr-1">
          {history.map((item, idx) => {
            const isQuarantined = item.quarantined || item.status === 'rejected';
            const isSelected = selectedIndex === idx;
            const enriched = item.enriched_incident_object;

            return (
              <button
                key={idx}
                type="button"
                onClick={() => onSelect(idx)}
                className={`w-full text-left p-2.5 rounded-xl border transition-all duration-200 font-mono text-xs ${
                  isSelected
                    ? 'bg-cyan-950/60 border-cyan-500/60 shadow-lg shadow-cyan-950/40'
                    : isQuarantined
                    ? 'bg-rose-950/20 border-rose-900/40 hover:border-rose-700/60'
                    : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="flex items-center space-x-1.5 font-semibold text-slate-300">
                    {isQuarantined ? (
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400 flex-shrink-0" />
                    ) : (
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                    )}
                    <span className="truncate max-w-[120px]">
                      {enriched?.structural_context?.source_ip || 'IP_UNK'}
                    </span>
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {item.pipeline_latency_ms.toFixed(0)}ms
                  </span>
                </div>

                <p className="text-[11px] text-slate-400 truncate">
                  {item.incident_hypothesis?.attack_type || 'Unknown'}
                </p>

                <div className="flex items-center justify-between mt-1 text-[10px] text-slate-500">
                  <span>Score: {item.composite_risk_score?.toFixed(2)}</span>
                  <span>{enriched?.timestamp ? new Date(enriched.timestamp).toLocaleTimeString() : ''}</span>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};
