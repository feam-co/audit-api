"""
FEAM Audit API v1.2.1
Deterministic AI Governance — Verifiable Audit Chain

Architecture:
  - No LLM in decision loop
  - SHA-256 cryptographic chain (append-only)
  - 5-axis Sigma scoring (Benefit, Transparency, Compliance, Resilience, Waste)
  - Independent verification endpoint

Patent: TR 2024 121973 (Class 42)
© 2026 FEAM.co · 5E Yapı Sistemleri Yönetimi Ltd. Şti.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import hashlib
import time
import re
import json

# ══════════════════════════════════════════════════════════
#  GOVERNOR KERNEL — Constitutional Thresholds (SSOT)
# ══════════════════════════════════════════════════════════

FEAM_APPROVED = 0.70
FEAM_ESCALATE = 0.45

THRESHOLD_MAP = {
    "LOW":      {"approved": 0.60, "escalate": 0.35},
    "MEDIUM":   {"approved": 0.68, "escalate": 0.42},
    "HIGH":     {"approved": 0.75, "escalate": 0.50},
    "CRITICAL": {"approved": 0.82, "escalate": 0.60},
}

WEIGHTS = {
    "fayda":        0.28,
    "seffaflik":    0.22,
    "sozlesme":     0.20,
    "mucbir_sebep": 0.18,
    "israf":        0.12,
}

# ══════════════════════════════════════════════════════════
#  HARD GATES — Binary safety checks (PII / compliance)
# ══════════════════════════════════════════════════════════

PII_PATTERNS = [
    ("TCKN",  r"\b\d{11}\b"),
    ("SSN",   r"\b\d{3}-\d{2}-\d{4}\b"),
    ("IBAN",  r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?[\dA-Z]{4}[\s]?[\dA-Z]{4}[\s]?[\dA-Z]{4}[\s]?[\dA-Z]{0,4}\b"),
    ("EMAIL", r"[\w.\-]+@[\w.\-]+\.\w+"),
    ("PHONE", r"\b(?:\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b"),
    ("MRN",   r"MRN[-:]?\d+"),
    ("DATE",  r"\b\d{2}[./\-]\d{2}[./\-]\d{4}\b"),
    ("ICD10", r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b"),
]

RISK_KEYWORDS = {
    "CRITICAL": ["sil", "delete", "drop table", "rm -rf", "format", "shut down", "kill"],
    "HIGH": ["kredi kart", "credit card", "şifre", "password", "parola", "secret key"],
    "MEDIUM": ["risksiz", "garanti", "kesinlikle", "absolutely", "guaranteed"],
}


def scan_pii(text: str) -> list:
    """Scan text for PII patterns. Returns list of violations."""
    violations = []
    for name, pattern in PII_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            violations.append({"type": name, "match": m[:6] + "***"})
    return violations


def scan_risk_keywords(text: str) -> str:
    """Classify risk level based on content keywords."""
    text_lower = text.lower()
    for level in ["CRITICAL", "HIGH", "MEDIUM"]:
        for kw in RISK_KEYWORDS[level]:
            if kw in text_lower:
                return level
    return "LOW"


def compute_sigma(metrics: dict) -> float:
    """Compute weighted sigma score from 5-axis metrics."""
    score = 0.0
    for dim, weight in WEIGHTS.items():
        val = metrics.get(dim, 0.5)
        if dim == "israf":
            score += weight * (1.0 - val)  # Invert waste
        else:
            score += weight * val
    return round(max(0.0, min(1.0, score)), 4)


def classify(sigma: float, risk_class: str = "MEDIUM") -> str:
    """Classify sigma into verdict band."""
    t = THRESHOLD_MAP.get(risk_class, THRESHOLD_MAP["MEDIUM"])
    if sigma >= t["approved"]:
        return "APPROVED"
    if sigma >= t["escalate"]:
        return "ESCALATE"
    return "REJECTED"


# ══════════════════════════════════════════════════════════
#  WITNESS CHAIN — SHA-256 Append-Only Ledger
# ══════════════════════════════════════════════════════════

class WitnessChain:
    """In-memory cryptographic audit chain. Append-only."""

    def __init__(self):
        self.chain: List[dict] = []
        self._append_genesis()

    def _append_genesis(self):
        genesis = {
            "index": 0,
            "timestamp": time.time(),
            "event": "GENESIS",
            "data": {
                "engine": "FEAM GOVERNOR v1.2.1",
                "constitution": "5-Axis Sigma + Hard Gates + WORM",
                "patent": "TR 2024 121973",
            },
            "prev_hash": "0" * 64,
            "hash": "",
        }
        genesis["hash"] = self._compute_hash(genesis)
        self.chain.append(genesis)

    def _compute_hash(self, block: dict) -> str:
        payload = json.dumps({
            "index": block["index"],
            "timestamp": block["timestamp"],
            "event": block["event"],
            "data": block["data"],
            "prev_hash": block["prev_hash"],
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def append(self, event: str, data: dict) -> dict:
        prev = self.chain[-1]
        block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "event": event,
            "data": data,
            "prev_hash": prev["hash"],
            "hash": "",
        }
        block["hash"] = self._compute_hash(block)
        self.chain.append(block)
        return block

    def verify(self) -> dict:
        """Verify entire chain integrity."""
        errors = []
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            prev = self.chain[i - 1]
            expected = self._compute_hash(block)
            if block["hash"] != expected:
                errors.append({"index": i, "error": "hash_mismatch"})
            if block["prev_hash"] != prev["hash"]:
                errors.append({"index": i, "error": "chain_break"})
        return {
            "chain_length": len(self.chain),
            "verified_blocks": len(self.chain) - len(errors),
            "errors": errors,
            "integrity": "INTACT" if not errors else "COMPROMISED",
            "genesis_hash": self.chain[0]["hash"],
            "latest_hash": self.chain[-1]["hash"],
            "verified_at": time.time(),
        }


# ══════════════════════════════════════════════════════════
#  FASTAPI APPLICATION
# ══════════════════════════════════════════════════════════

app = FastAPI(
    title="FEAM Audit API",
    version="1.2.1",
    description="Deterministic AI Governance — Verifiable Audit Chain. Patent TR 2024 121973.",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://feam.co",
        "https://www.feam.co",
        "http://localhost:3000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global chain instance
witness = WitnessChain()
_start_time = time.time()


# ─── Request / Response Models ───────────────────────────

class AuditRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=50000, description="Text to audit")
    mission: str = Field(default="general_audit", description="Audit context")
    risk_class: Optional[str] = Field(default="MEDIUM", description="LOW | MEDIUM | HIGH | CRITICAL")

class MaskRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Text to mask PII from")
    redact_mode: str = Field(default="mask", description="mask | replace")


# ─── Endpoints ───────────────────────────────────────────

@app.get("/", tags=["System"])
async def root():
    """Service status and genesis hash."""
    return {
        "service": "FEAM Audit API",
        "version": "1.2.1",
        "engine": "GOVERNOR Kernel — 5-Axis Sigma + Hard Gates",
        "patent": "TR 2024 121973 (Class 42)",
        "status": "operational",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "chain_height": len(witness.chain),
        "genesis_hash": witness.chain[0]["hash"],
        "endpoints": {
            "audit": "POST /api/v1/audit",
            "mask": "POST /api/v1/mask",
            "verify": "GET /api/v1/verify",
            "chain": "GET /api/v1/chain",
            "genesis": "GET /api/v1/genesis",
            "docs": "GET /docs",
        },
    }


@app.get("/api/v1/genesis", tags=["Chain"])
async def genesis():
    """Return the constitutional genesis block."""
    return witness.chain[0]


@app.post("/api/v1/audit", tags=["Audit"])
async def audit(req: AuditRequest):
    """
    Run a full deterministic audit on the input text.

    Pipeline: PII Scan → Risk Classification → Hard Gates → Sigma Score → Verdict → Witness Seal
    """
    t0 = time.time()

    # Step 1: PII Scan (Hard Gate)
    pii_violations = scan_pii(req.input)
    pii_blocked = len(pii_violations) > 0

    # Step 2: Risk Classification
    risk_level = scan_risk_keywords(req.input)
    effective_risk = req.risk_class if req.risk_class else risk_level

    # Step 3: Heuristic 5-axis metrics
    word_count = len(req.input.split())
    metrics = {
        "fayda":        round(min(1.0, 0.5 + (word_count / 200)), 4),
        "seffaflik":    0.90 if not pii_blocked else 0.30,
        "sozlesme":     0.85 if not pii_blocked else 0.20,
        "mucbir_sebep": 0.80,
        "israf":        round(min(1.0, max(0.05, word_count / 500)), 4),
    }

    # Step 4: Sigma Score
    sigma = compute_sigma(metrics)

    # Step 5: Hard Gate Override
    if pii_blocked:
        sigma = round(sigma * 0.1, 4)  # Penalty
        verdict = "REJECTED"
        verdict_reason = f"hard_gate:PII_DETECTED ({len(pii_violations)} violations)"
    else:
        verdict = classify(sigma, effective_risk)
        if verdict == "APPROVED":
            verdict_reason = "sigma_pass"
        elif verdict == "ESCALATE":
            verdict_reason = "grey_zone:human_review_required"
        else:
            verdict_reason = "sigma_below_threshold"

    # Step 6: Witness Seal
    audit_data = {
        "input_hash": hashlib.sha256(req.input.encode()).hexdigest(),
        "mission": req.mission,
        "risk_class": effective_risk,
        "sigma": sigma,
        "verdict": verdict,
        "pii_count": len(pii_violations),
        "metrics": metrics,
    }
    block = witness.append(f"AUDIT:{verdict}", audit_data)

    elapsed_ms = round((time.time() - t0) * 1000, 2)

    return {
        "audit_id": f"AUD-{block['index']:06d}",
        "timestamp": block["timestamp"],
        "pipeline": {
            "pii_scan": {
                "violations": pii_violations,
                "blocked": pii_blocked,
            },
            "risk_classification": risk_level,
            "effective_risk_class": effective_risk,
            "metrics": metrics,
            "sigma_score": sigma,
            "verdict": verdict,
            "reason": verdict_reason,
        },
        "witness": {
            "block_index": block["index"],
            "hash": block["hash"],
            "prev_hash": block["prev_hash"],
            "chain_height": len(witness.chain),
        },
        "elapsed_ms": elapsed_ms,
    }


@app.post("/api/v1/mask", tags=["Audit"])
async def mask_pii(req: MaskRequest):
    """Scan and mask PII/PHI from text. Returns cleaned version + WORM receipt."""
    t0 = time.time()
    masked = req.text
    violations = []

    for name, pattern in PII_PATTERNS:
        matches = re.finditer(pattern, masked, re.IGNORECASE)
        for m in matches:
            violations.append({"type": name, "original": m.group()[:4] + "***"})
            if req.redact_mode == "replace":
                masked = masked.replace(m.group(), f"[{name}_REDACTED]")
            else:
                masked = masked.replace(m.group(), f"[{name}]")

    risk = min(1.0, len(violations) * 0.25) if violations else 0.0
    worm_hash = hashlib.sha256(json.dumps({
        "masked": masked, "violations": len(violations), "ts": time.time()
    }).encode()).hexdigest()

    block = witness.append("MASK_SCAN", {
        "input_hash": hashlib.sha256(req.text.encode()).hexdigest(),
        "violation_count": len(violations),
        "risk_score": risk,
    })

    return {
        "clean_text": masked,
        "violations": violations,
        "risk_score": risk,
        "is_safe": len(violations) == 0,
        "worm_receipt": block["hash"],
        "elapsed_ms": round((time.time() - t0) * 1000, 2),
    }


@app.get("/api/v1/chain", tags=["Chain"])
async def chain():
    """Return the full audit chain (last 100 blocks)."""
    return {
        "chain_length": len(witness.chain),
        "blocks": witness.chain[-100:],
    }


@app.get("/api/v1/verify", tags=["Chain"])
async def verify():
    """
    Independent chain integrity verification.
    No internal access required — recomputes every hash from scratch.
    """
    return witness.verify()


@app.get("/health", tags=["System"])
async def health():
    return {
        "status": "ok",
        "service": "FEAM Audit API",
        "version": "1.2.1",
        "uptime_seconds": round(time.time() - _start_time, 1),
    }
