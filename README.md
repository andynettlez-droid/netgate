# NetGate: Enterprise GitOps Network Compliance Platform

![NetGate Dashboard Demo](./frontend/public/demo.png) <!-- Note: Add a screenshot of the dashboard here! -->

NetGate is an advanced, Zero-Trust compliance platform that bridges the gap between infrastructure-as-code and enterprise governance. It provides mathematically verifiable network validation, multi-signature approval gates, and a cryptographically immutable ledger to completely eliminate human-error in network deployments.

## 🚀 The Problem

Modern networks are fragile. A single incorrect ACL or missing BGP route can cause catastrophic enterprise outages. Traditional network management relies on human review and reactive troubleshooting.

## 🛡️ The Solution: NetGate

NetGate introduces **Pre-Flight Emulation** and **Cryptographic Governance**. Before a configuration is ever pushed to a live Cisco, Arista, or Juniper router, NetGate simulates the data-plane, verifies regulatory compliance, and requires multi-signature human sign-off recorded on an immutable ledger.

### Core Features

*   **🔍 Mathematical Data-Plane Verification:** Simulates end-to-end traceroutes and reachability across the proposed topology *before* deployment.
*   **🤖 AI Auto-Remediation:** Automatically generates context-aware CLI patches to fix security vulnerabilities (e.g., missing SSH transport layers, weak passwords).
*   **🔐 Zero-Trust RBAC & Multi-Sig Gates:** Strict separation of duties. Deployments require cryptographic co-signatures from both a `Security Auditor` and a `Release Manager`.
*   **📜 Immutable Governance Ledger:** Every deployment, webhook, and approval signature is chained via SHA-256 hashes, generating an unbreakable Merkle-tree audit trail.
*   **🏦 SOC2 Type II Automated Export:** Instantly exports verifiable compliance reports for third-party regulatory auditing.

---

## 🏗️ Architecture

NetGate is built using a modern, decoupled architecture designed for high-throughput CI/CD pipelines.

*   **Frontend:** React (Vite) + Vanilla CSS. Built with a responsive, glassmorphic UI, dynamic topology mapping, and real-time state synchronization.
*   **Backend:** Python + FastAPI. Chosen for its extreme performance, asynchronous I/O, and native OpenAPI documentation generation.
*   **Security:** JSON Web Token (JWT) authentication, Base64 payload decoding, and SHA-256 cryptographic hashing for ledger integrity.

---

## 💻 Local Development Setup

To run the simulation sandbox locally, you will need Node.js and Python 3.10+ installed.

### 1. Start the FastAPI Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Or `venv\Scripts\activate` on Windows
pip install fastapi uvicorn pydantic
uvicorn main:app --reload --port 8000
```

### 2. Start the React Frontend
Open a new terminal window:
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:5173`. 
*(Note: To test the Zero-Trust SSO, login with username `sjenkins` for Admin access, or `mvance` for Security Auditor access).*

---

## 🧠 Why I Built This (Interview Context)

I built NetGate to demonstrate a deep understanding of the intersection between **Software Engineering**, **Cybersecurity**, and **Enterprise Operations**. 

While many engineers build standard CRUD apps, I wanted to build a complex system that solves a highly technical, high-stakes problem: safely automating critical infrastructure. This project demonstrates my ability to:
1.  Architect decoupled systems (REST APIs, React frontends).
2.  Implement advanced security patterns (JWTs, Role-Based Access Control).
3.  Design fault-tolerant governance models (Cryptographic Ledgers, Multi-Sig approvals).
4.  Translate complex backend logic into an intuitive, beautiful user interface.

## 📝 License
MIT License. Free to use, modify, and distribute.
