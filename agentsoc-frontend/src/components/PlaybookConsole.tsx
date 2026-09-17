import React, { useState } from 'react';
import { ShieldAlert, Gauge, Lock, CheckCircle, Copy, Check, ChevronRight } from 'lucide-react';
import type { PlaybookWorkflow } from '../types/soc';

interface PlaybookConsoleProps {
  workflow: PlaybookWorkflow | null;
  riskScore: number | null;
  auditRef: string | null;
}

export const PlaybookConsole: React.FC<PlaybookConsoleProps> = ({ workflow, riskScore, auditRef }) => {
  const [copiedAudit, setCopiedAudit] = useState<boolean>(false);

  if (!workflow) {
    return (
      <div className="cyber-glass-card rounded-2xl p-6 border border-slate-800/80 shadow-2xl flex flex-col items-center justify-center text-center min-h-[220px]">
        <ShieldAlert className="w-8 h-8 text-slate-700 animate-pulse mb-2" />
        <h3 className="text-xs font-semibold text-slate-400">Playbook Engine Standing By</h3>
        <p className="text-[11px] text-slate-600 mt-1">Remediation steps & WORM audit log will generate upon telemetry ingestion.</p>
      </div>
    );
  }

  if (workflow.mode === "OFFLINE") {
    return (
      <div className="cyber-glass-card rounded-2xl p-6 border border-slate-800/80 shadow-2xl flex flex-col items-center justify-center text-center min-h-[220px]">
        <ShieldAlert className="w-8 h-8 text-slate-600 mb-2" />
        <h3 className="text-slate-300 font-semibold uppercase tracking-widest text-sm">Playbook Offline</h3>
        <p className="text-slate-500 text-xs font-mono mt-1">Awaiting LM Studio Connection for Risk Computation.</p>
      </div>
    );
  }

  const handleCopyAudit = () => {
    if (auditRef) {
      navigator.clipboard.writeText(auditRef);
      setCopiedAudit(true);
      setTimeout(() => setCopiedAudit(false), 2000);
    }
  };

  const isHighRisk = (riskScore ?? 0) > 0.6;

  return (
    <div className="cyber-glass-card rounded-2xl p-5 border border-slate-800/80 shadow-2xl space-y-4">
      {/* Panel Header */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center space-x-2.5">
          <Gauge className="w-5 h-5 text-amber-400" />
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            Risk Score & Adaptive Playbook
          </h2>
        </div>
        <span className={`text-[11px] font-mono px-2 py-0.5 rounded font-bold ${
          isHighRisk ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
        }`}>
          {workflow.severity}
        </span>
      </div>

      {/* Composite Risk Score Meter */}
      <div className="bg-slate-950/60 rounded-xl p-4 border border-slate-800/80 space-y-4">
        <div className="flex justify-between items-end">
          <div>
            <span className="text-xs font-mono text-slate-400 block uppercase tracking-wider mb-1">Composite Risk Score</span>
            <div className="flex items-baseline space-x-2">
              <span className={`text-3xl font-bold font-mono tracking-tight ${
                isHighRisk ? 'text-rose-400 drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]' : 'text-emerald-400 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]'
              }`}>
                {riskScore !== null ? riskScore.toFixed(1) : '--'}
              </span>
              <span className="text-xs text-slate-500 font-mono">/ 100.0</span>
            </div>
          </div>
          <div className="text-right">
            <span className="text-[10px] font-mono text-slate-500 block uppercase">Primary Action</span>
            <span className={`text-sm font-bold font-mono block mt-0.5 ${
              isHighRisk ? 'text-rose-300' : 'text-emerald-300'
            }`}>
              {workflow.primary_action}
            </span>
          </div>
        </div>

        {/* Visual Progress Bar */}
        <div className="relative h-2.5 w-full bg-slate-900 rounded-full overflow-hidden border border-slate-800/60 shadow-inner">
          <div 
            className={`absolute top-0 left-0 h-full transition-all duration-1000 ease-out rounded-full ${
              isHighRisk ? 'bg-gradient-to-r from-rose-600 to-rose-400' : 'bg-gradient-to-r from-emerald-600 to-emerald-400'
            }`}
            style={{ width: `${Math.min(Math.max((riskScore || 0), 0), 100)}%` }}
          />
        </div>
      </div>

      {/* Playbook Execution Steps */}
      {workflow.execution_steps && workflow.execution_steps.length > 0 && (
        <div className="space-y-2">
          <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1">
            <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />
            <span>Automated Containment Workflow Steps:</span>
          </span>
          <div className="space-y-1.5 font-mono text-xs">
            {workflow.execution_steps.map((step, idx) => (
              <div
                key={idx}
                className="flex items-start space-x-2 bg-slate-900/70 p-2 rounded-lg border border-slate-800 text-slate-300"
              >
                <CheckCircle className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                <span>{step}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Immutable WORM Audit Reference */}
      {auditRef && (
        <div className="bg-gradient-to-r from-purple-950/40 via-slate-900 to-indigo-950/40 p-3 rounded-xl border border-purple-800/40 font-mono text-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-purple-300 uppercase tracking-wider flex items-center space-x-1">
              <Lock className="w-3 h-3 text-purple-400" />
              <span>Sovereign Audit Lock (180-Day WORM)</span>
            </span>
            <button
              type="button"
              onClick={handleCopyAudit}
              className="text-purple-400 hover:text-purple-200 transition-colors flex items-center space-x-1 text-[10px]"
            >
              {copiedAudit ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedAudit ? 'COPIED' : 'COPY REF'}</span>
            </button>
          </div>
          <p className="text-xs font-bold text-purple-200 break-all">{auditRef}</p>
        </div>
      )}
    </div>
  );
};
