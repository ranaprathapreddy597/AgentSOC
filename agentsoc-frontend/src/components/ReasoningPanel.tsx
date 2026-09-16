import React from 'react';
import { Cpu, Target, Shield } from 'lucide-react';
import type { IncidentHypothesis } from '../types/soc';

interface ReasoningPanelProps {
  hypothesis: IncidentHypothesis | null;
  simulationValid: boolean | null;
}

export const ReasoningPanel: React.FC<ReasoningPanelProps> = ({ hypothesis, simulationValid }) => {
  if (!hypothesis) {
    return (
      <div className="cyber-glass-card rounded-2xl p-6 border border-slate-800/80 shadow-2xl flex flex-col items-center justify-center text-center min-h-[220px]">
        <Cpu className="w-8 h-8 text-slate-700 animate-pulse mb-2" />
        <h3 className="text-xs font-semibold text-slate-400">MAED Consensus Engine Idle</h3>
        <p className="text-[11px] text-slate-600 mt-1">Awaiting Red/Blue Epistemic Debate via incoming telemetry.</p>
      </div>
    );
  }

  const confidencePercent = Math.round(hypothesis.confidence_score * 100);

  const getConfidenceBarColor = (score: number) => {
    if (score >= 0.9) return 'bg-gradient-to-r from-emerald-600 to-emerald-400';
    if (score >= 0.7) return 'bg-gradient-to-r from-amber-600 to-amber-400';
    return 'bg-gradient-to-r from-rose-600 to-rose-400';
  };

  return (
    <div className="cyber-glass-card rounded-2xl p-5 border border-slate-800/80 shadow-2xl space-y-4">
      {/* Panel Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center space-x-2.5">
          <Cpu className="w-5 h-5 text-indigo-400" />
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            MAED Epistemic Debate
          </h2>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-800/60 shadow-[0_0_8px_rgba(99,102,241,0.2)]">
          Consensus Score
        </span>
      </div>

      {/* Attack Categorization */}
      <div className="bg-slate-950/60 rounded-xl p-3.5 border border-slate-800/80 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-400">DETECTED ATTACK TYPE:</span>
          {simulationValid !== null && (
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
              simulationValid ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
            }`}>
              {simulationValid ? 'Topology Path Valid' : 'Hallucination Rejected'}
            </span>
          )}
        </div>
        <p className="text-sm font-bold font-mono text-cyan-300">{hypothesis.attack_type}</p>
      </div>

      {/* Confidence Score Bar */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">Red/Blue Consensus Score:</span>
          <span className="font-bold text-slate-200">{confidencePercent}%</span>
        </div>
        <div className="w-full bg-slate-900 rounded-full h-2.5 p-0.5 border border-slate-800 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${getConfidenceBarColor(hypothesis.confidence_score)}`}
            style={{ width: `${confidencePercent}%` }}
          />
        </div>
      </div>

      {/* MITRE ATT&CK Tactics */}
      {hypothesis.mitre_tactics && hypothesis.mitre_tactics.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1">
            <Target className="w-3.5 h-3.5 text-rose-400" />
            <span>MITRE ATT&CK Tactics:</span>
          </span>
          <div className="flex flex-wrap gap-2">
            {hypothesis.mitre_tactics.map((tactic, idx) => (
              <span
                key={idx}
                className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-rose-500/10 text-rose-300 border border-rose-500/30 font-semibold"
              >
                {tactic}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Directive */}
      <div className="bg-slate-900/80 rounded-xl p-3 border border-slate-800 text-xs space-y-1">
        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
          Recommended Response Directive:
        </span>
        <div className="flex items-center space-x-2 text-cyan-300 font-semibold font-mono">
          <Shield className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span>{hypothesis.recommended_action}</span>
        </div>
      </div>
    </div>
  );
};
