# LinkGuard 🛡️

**LinkGuard** is an AI-powered URL safety and web threat inspection agent built with the Google Agent Development Kit (ADK) and deployed to Google Cloud Agent Platform.

When provided with any URL or web link, LinkGuard follows an automated inspection workflow:
1. Resolves full redirect chains and checks HTTP response status and security headers.
2. Captures a live headless browser screenshot of the destination page.
3. Performs threat reasoning with Gemini (`gemini-3.6-flash`) to categorize threats (Phishing, Scam / Deceptive, Malware, Defacement, or Clean) and determine a verdict (`Good`, `Suspicious`, or `Malicious`).
4. Persists the audit record in Google Cloud BigQuery and stores the visual evidence in Google Cloud Storage.
5. Formats the findings into structured Agent-to-UI (**A2UI v0.8**) display cards with inline screenshot rendering and resilient markdown fallbacks.

---

## 🛠️ Architecture & Google Cloud Integration

The capabilities implemented in this repository are grounded in the following services and tools:

| Component / Layer | Technology | Actual Implementation |
| :--- | :--- | :--- |
| **Agent Core** | Google ADK + `agents-cli` | Agent loop running Gemini `gemini-3.6-flash` (`app/agent.py`) |
| **Inspection Tool** | Python + Headless Chrome | Resolves HTTP redirects, inspects headers/DOM, captures screenshot (`app/tools.py::inspect_and_capture_url`) |
| **Audit Persistence** | Google Cloud BigQuery | Direct streaming insert into `linkguard_data.url_scans` table (`app/tools.py::store_scan_result`) |
| **Evidence Storage** | Google Cloud Storage | Stores scan JSON logs (`scans/*.json`) and preview screenshots (`screenshots/*.png`) with public HTTPS URIs |
| **History Tool** | Google Cloud Storage | Queries previous scan audit logs by domain/URL (`app/tools.py::lookup_scan_history`) |
| **Agent UI** | A2UI (v0.8 Basic Catalog) | Custom after-model callback translating threat verdicts and screenshots into A2UI `beginRendering` & `surfaceUpdate` specifications (`app/a2ui_utils.py`) |

### Status of Planned Features from Project Brief
- **BigQuery Audit Logging**: **Implemented** (`linkguard_data.url_scans`).
- **Cloud Storage Screenshot & Log Persistence**: **Implemented** (`gs://<bucket>/screenshots/`, `gs://<bucket>/scans/`).
- **Headless Page Capture & Threat Classification**: **Implemented** (Headless Chrome + Gemini reasoning).
- **A2UI Visual Cards**: **Implemented** (v0.8 Basic Catalog schema with resilient markdown fallback).
- **Long-term Cross-session Memory Bank**: *Planned, not yet implemented* (scans are tracked via BigQuery/GCS audit tools; Vertex AI Memory Bank integration is not yet wired).
- **Firestore**: *Planned, not yet implemented* (BigQuery and Cloud Storage are used for structured and object persistence).

---

## 📋 Repository Structure

```text
linkguard/
├── app/
│   ├── agent.py               # Main agent configuration, A2UI prompt schema, and tools registration
│   ├── tools.py               # inspect_and_capture_url, store_scan_result, lookup_scan_history
│   └── a2ui_utils.py          # A2UI v0.8 response converter and fallback renderer
├── agents-cli-manifest.yaml   # Agent manifest configuration
├── pyproject.toml             # Project dependencies (ADK, google-genai, a2ui-agent-sdk, etc.)
└── tests/                     # Unit and integration test suite
```

---

## 🚀 Running Locally

### 1. Prerequisites
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- Google Cloud SDK (`gcloud`) authenticated to your GCP project:
  ```bash
  gcloud auth login
  gcloud auth application-default login
  ```
- Google Chrome installed on the host system (for headless screenshot capture)

### 2. Environment Setup
Configure the environment variables in a `.env` file within the project directory:

```bash
GOOGLE_CLOUD_PROJECT="<your-gcp-project-id>"
GOOGLE_CLOUD_LOCATION="us-east1"
BUCKET_NAME="<your-gcs-bucket-name>"
```

### 3. Installation
Install the project dependencies and setup the virtual environment:

```bash
agents-cli install
```

### 4. Start the Agent Playground
Launch the local ADK developer environment:

```bash
agents-cli playground
```

Once started, open the local playground interface provided in the terminal to inspect target URLs (e.g., `Check if https://snapchat.com is safe`).

---

## ☁️ Deployment

To deploy the agent to Vertex AI Agent Runtime:

```bash
agents-cli deploy
```
