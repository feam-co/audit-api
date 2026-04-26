# FEAM Audit API

> Deterministic AI Governance — Verifiable Audit Chain

AI risk and compliance verification layer powered by the FEAM GOVERNOR kernel.  
No LLM in the decision loop. Rules decide. Cryptography proves.

**Live:** [feam-audit-api.onrender.com](https://feam-audit-api.onrender.com)  
**Web:** [feam.co/audit](https://feam.co/audit)  
**Patent:** TR 2024 121973 (Class 42)

## Architecture

```
Input → PII Scan → Risk Classification → Hard Gates → 5-Axis Sigma → Verdict → Witness Seal
         │              │                    │              │              │
         └── TCKN/SSN   └── Keyword-based    └── Binary     └── Weighted   └── SHA-256
             IBAN/Email      risk level          pass/fail      composite      chain append
             MRN/Phone                                          score
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Service status & genesis hash |
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/genesis` | Constitutional genesis block |
| `POST` | `/api/v1/audit` | Full risk audit pipeline |
| `POST` | `/api/v1/mask` | PII/PHI masking with WORM receipt |
| `GET` | `/api/v1/chain` | Full audit chain (last 100 blocks) |
| `GET` | `/api/v1/verify` | Independent chain integrity verification |
| `GET` | `/docs` | Interactive Swagger UI |

## Quick Test

```bash
# Health check
curl https://feam-audit-api.onrender.com/

# Full audit
curl -X POST https://feam-audit-api.onrender.com/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"input":"Bu yatırım kesinlikle risksizdir.","mission":"audit_ai_output"}'

# PII masking
curl -X POST https://feam-audit-api.onrender.com/api/v1/mask \
  -H "Content-Type: application/json" \
  -d '{"text":"Hasta Ahmet Yılmaz (TC: 12345678901) raporu"}'

# Chain verification
curl https://feam-audit-api.onrender.com/api/v1/verify
```

## Sigma Scoring

5-axis deterministic scoring from canonical thresholds:

| Axis | Weight | Description |
|------|--------|-------------|
| Benefit (fayda) | 28% | Value delivered |
| Transparency (şeffaflık) | 22% | Explainability |
| Compliance (sözleşme) | 20% | Contract/legal adherence |
| Resilience (mücbir sebep) | 18% | Safe execution capacity |
| Waste (israf) | 12% | Resource waste (inverted) |

**Verdict bands:** `APPROVED` (σ ≥ 0.68) → `ESCALATE` (σ ≥ 0.42) → `REJECTED`

## EU AI Act Compliance

- **Article 9:** 5-axis risk scoring with configurable thresholds
- **Article 12:** SHA-256 WORM chain — append-only, tamper-evident
- **Article 13:** Full decision explainability in every response
- **Article 14:** Human escalation for grey-zone decisions

## Status

TRL 4 — Working prototype. Persistent storage (PostgreSQL) on roadmap for v1.3.

## License

© 2026 FEAM.co · 5E Yapı Sistemleri Yönetimi Ltd. Şti.
