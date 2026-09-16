export interface StructuralContext {
  source_ip: string;
  target_ip: string;
  criticality: string;
  zone: string;
}

export interface EnrichedIncidentObject {
  incident_id: string;
  timestamp: string;
  sanitized_payload: string;
  structural_context: {
    source_ip: string;
    target_ip: string;
    criticality: string;
    zone: string;
  };
  security_flags: string[];
}

export interface IncidentHypothesis {
  attack_type: string;
  confidence_score: number;
  mitre_tactics: string[];
  recommended_action: string;
}

export interface GuardrailResult {
  status: "allowed" | "blocked";
  confidence: number;
  latency_ms: number;
}

export interface PlaybookWorkflow {
  primary_action: string;
  severity: "CRITICAL" | "HIGH" | "LOW_MEDIUM";
  risk_score_evaluated: number;
  mitre_tactics: string[];
  execution_steps: string[];
}

export interface IngestResponse {
  status: "success" | "rejected";
  quarantined?: boolean;
  reason?: string;
  guardrail?: GuardrailResult;
  enriched_incident_object?: EnrichedIncidentObject;
  incident_hypothesis: IncidentHypothesis;
  simulation_valid: boolean;
  composite_risk_score: number;
  playbook_workflow: PlaybookWorkflow;
  audit_log_ref: string;
  processed_payload?: string;
  pipeline_latency_ms: number;
  sandbox_confirmation?: {
    status: string;
    container_id: string;
    target_ip: string;
    timestamp: string;
  } | null;
}
