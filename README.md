# 🛡️ AgentSOC: Multi-Agent SIEM & Threat Mitigation Platform

AgentSOC is an enterprise-grade, zero-trust AI security pipeline designed to ingest, analyze, and contain adversarial telemetry locally. By combining a local multi-agent AI swarm with graph-based threat intelligence, it reduces latency and preserves privacy without relying on cloud-based security services.

The platform is built to enforce a sub-500ms service-level objective for end-to-end threat mitigation while keeping sensitive data protected at the edge.

---

## ⚡ Core Architecture

AgentSOC follows a hybrid edge-AI approach where sensitive data is scrubbed at the ingestion layer before complex reasoning is delegated to a local swarm of specialized agents.

- Triage Agent: filters telemetry noise, validates structure, and evaluates guardrail signals.
- Graph Forensics Agent: executes fast graph queries to validate lateral movement paths and map activity to MITRE ATT&CK tactics.
- Remediation Agent: computes dynamic risk scores and synthesizes containment playbooks for response actions.

---

## 🚀 Key Features

- Sub-500ms mitigation engine with local ingestion, redaction, and reasoning.
- Hardware-accelerated SLM guardrails using ONNX Runtime for prompt injection and context-stitching detection.
- GraphRAG threat intelligence powered by KùzuDB and Qdrant for historical and real-time correlation.
- Stateful temporal memory to detect fragmented multi-stage attack patterns.
- Zero-trust PII redaction using deterministic masking before model ingestion.
- Real-time WebSocket UI for streaming enriched telemetry and AI reasoning.

---

## 🛠️ Technology Stack

### Frontend
- React 18 and TypeScript
- Vite
- Tailwind CSS and shadcn/ui
- Lucide React

### Backend
- FastAPI and Uvicorn
- Python 3.13 with uv
- Pydantic for schema enforcement

### AI and Data Layer
- LLM engine: LM Studio (Qwen 2.5 / Llama 3)
- SLM guardrail: Hugging Face ONNX Runtime
- Graph memory: KùzuDB
- Vector memory: Qdrant
- NLP and masking: Microsoft Presidio and SpaCy

---

## ⚙️ Quick Start

AgentSOC is designed to run locally without requiring external cloud dependencies.

### Prerequisites
- uv for Python package management
- Node.js and npm for the frontend
- LM Studio running locally at http://localhost:1234/v1

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/AgentSOC.git
cd AgentSOC
```

### 2. Start the Backend API

```bash
uv pip install -r requirements.txt
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000
```

### 3. Start the SOC Dashboard

```bash
cd agentsoc-frontend
npm install
npm run dev
```

Open http://localhost:5173 to access the dashboard.

---

## 🧪 Running the Test Suite

```bash
uv run pytest tests/ -v
```

---

## 📐 Risk Scoring Logic

The remediation agent computes threat severity using the following formula:

$$
Composite\ Score = (0.7 \times Containment) - (0.3 \times Impact)
$$

Any score above 0.60 automatically triggers an isolate-host directive.

---

## 👨‍💻 Author

Rana Prathap Reddy

- AI Systems Architect and Backend Developer
- Focus: agentic workflows, RAG, and high-performance cybersecurity automation