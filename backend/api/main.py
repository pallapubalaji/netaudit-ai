"""
NetAudit AI - FastAPI Backend REST API Server
Provides endpoints for audit runs, drift detection, attack paths, what-if simulations, and AI recommendations.
"""

from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.parsers.detector import VendorDetector
from backend.parsers.cisco import CiscoParser
from backend.parsers.fortinet import FortinetParser
from backend.parsers.paloalto import PaloAltoParser
from backend.rules.engine import ComplianceEngine
from backend.risk.scoring import RiskScoringEngine
from backend.drift.detector import DriftDetector
from backend.attack_paths.graph import AttackPathAnalyzer
from backend.simulation.simulator import WhatIfSimulator
from backend.ai.analyst import AISecurityAnalyst
from backend.normalization.models import VendorEnum

app = FastAPI(
    title="NetAudit AI - API",
    description="Multi-Vendor Network Security Compliance Auditor & Risk Engine",
    version="1.0.0",
)

# Enable CORS for Frontend Development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Singleton Engine Instances
compliance_engine = ComplianceEngine()
risk_engine = RiskScoringEngine()
drift_detector = DriftDetector()
attack_path_analyzer = AttackPathAnalyzer()
simulation_engine = WhatIfSimulator()
ai_analyst = AISecurityAnalyst()


class SimulationRequest(BaseModel):
    config_text: str
    target_rule_id: str
    new_source_ip_or_subnet: str


class DriftRequest(BaseModel):
    old_config_text: str
    new_config_text: str


class AIExplainRequest(BaseModel):
    config_text: str
    finding_index: int = 0


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "platform": "NetAudit AI",
        "supported_vendors": ["cisco", "fortinet", "paloalto"],
        "engine_status": "ready",
    }


@app.post("/api/audit/upload")
async def audit_config_upload(
    file: Optional[UploadFile] = File(None),
    raw_config: Optional[str] = Form(None),
):
    """
    Ingests raw configuration (file upload or form text), auto-detects vendor,
    parses into Common Normalized Security Model, runs compliance rules,
    calculates explainable 0-100 risk score, builds attack paths, and generates executive AI summary.
    """
    if file:
        content_bytes = await file.read()
        config_text = content_bytes.decode("utf-8", errors="ignore")
    elif raw_config:
        config_text = raw_config
    else:
        raise HTTPException(status_code=400, detail="Must provide either a file upload or raw_config text.")

    if not config_text.strip():
        raise HTTPException(status_code=400, detail="Configuration content is empty.")

    # 1. Vendor Detection
    vendor = VendorDetector.detect_vendor(config_text)

    # 2. Select Vendor Parser
    if vendor == VendorEnum.CISCO:
        parser = CiscoParser()
    elif vendor == VendorEnum.FORTINET:
        parser = FortinetParser()
    elif vendor == VendorEnum.PALO_ALTO:
        parser = PaloAltoParser()
    else:
        # Fallback to Cisco parser for generic syntax attempt
        parser = CiscoParser()

    norm_config = parser.parse(config_text)

    # 3. Deterministic Compliance Audit
    findings = compliance_engine.run_audit(norm_config)

    # 4. Explainable 0-100 Risk Score
    risk_breakdown = risk_engine.calculate_risk(findings, norm_config)

    # 5. Attack-Path Exposure Analysis
    attack_paths = attack_path_analyzer.analyze_attack_paths(norm_config, findings)

    # 6. AI Security Summary
    ai_summary = ai_analyst.generate_executive_summary(norm_config, findings)

    # Convert Pydantic objects to dicts for clean JSON response
    return {
        "vendor": norm_config.vendor.value,
        "device_name": norm_config.device_name,
        "os_version": norm_config.os_version,
        "raw_hash": norm_config.raw_hash,
        "raw_line_count": norm_config.raw_line_count,
        "risk": risk_breakdown.model_dump(),
        "findings_count": len(findings),
        "findings": [f.model_dump() for f in findings],
        "attack_paths": [p.model_dump() for p in attack_paths],
        "ai_summary": ai_summary,
        "interfaces_count": len(norm_config.interfaces),
        "security_rules_count": len(norm_config.security_rules),
        "raw_config_preview": config_text.splitlines()[:50],
    }


@app.post("/api/drift/compare")
def compare_drift(req: DriftRequest):
    """Detects configuration drift and calculates security posture score deltas between two versions."""
    v1_vendor = VendorDetector.detect_vendor(req.old_config_text)
    v2_vendor = VendorDetector.detect_vendor(req.new_config_text)

    p1 = CiscoParser() if v1_vendor == VendorEnum.CISCO else (FortinetParser() if v1_vendor == VendorEnum.FORTINET else PaloAltoParser())
    p2 = CiscoParser() if v2_vendor == VendorEnum.CISCO else (FortinetParser() if v2_vendor == VendorEnum.FORTINET else PaloAltoParser())

    v1_norm = p1.parse(req.old_config_text)
    v2_norm = p2.parse(req.new_config_text)

    v1_findings = compliance_engine.run_audit(v1_norm)
    v2_findings = compliance_engine.run_audit(v2_norm)

    v1_risk = risk_engine.calculate_risk(v1_findings, v1_norm)
    v2_risk = risk_engine.calculate_risk(v2_findings, v2_norm)

    drift_report = drift_detector.compare_versions(v1_norm, v2_norm, v1_risk, v2_risk, v1_findings, v2_findings)
    return drift_report.model_dump()


@app.post("/api/simulation/run")
def run_simulation(req: SimulationRequest):
    """Executes in-memory dry-run policy modification and measures risk score reduction."""
    vendor = VendorDetector.detect_vendor(req.config_text)
    parser = CiscoParser() if vendor == VendorEnum.CISCO else (FortinetParser() if vendor == VendorEnum.FORTINET else PaloAltoParser())

    norm_config = parser.parse(req.config_text)
    sim_result = simulation_engine.simulate_rule_modification(
        original_config=norm_config,
        target_rule_id=req.target_rule_id,
        new_source_ip_or_subnet=req.new_source_ip_or_subnet,
    )
    return sim_result.model_dump()


@app.post("/api/ai/explain")
def explain_finding(req: AIExplainRequest):
    """Generates AI analysis and multi-vendor CLI remediation for a target finding."""
    vendor = VendorDetector.detect_vendor(req.config_text)
    parser = CiscoParser() if vendor == VendorEnum.CISCO else (FortinetParser() if vendor == VendorEnum.FORTINET else PaloAltoParser())

    norm_config = parser.parse(req.config_text)
    findings = compliance_engine.run_audit(norm_config)

    if not findings:
        return {"explanation": "No compliance findings present in configuration."}

    idx = max(0, min(req.finding_index, len(findings) - 1))
    target_finding = findings[idx]

    explanation = ai_analyst.generate_finding_explanation(target_finding, norm_config.vendor)
    return explanation
