"""
HeaderGuard Scoring Engine
Weights:
  CORS (Access-Control-Allow-Origin)  : 25pts
  CSP (Content-Security-Policy)       : 25pts
  HSTS (Strict-Transport-Security)    : 20pts
  X-Frame-Options                     : 10pts
  X-Content-Type-Options              : 10pts
  Referrer-Policy                     : 5pts
  Permissions-Policy                  : 5pts
Total: 100pts
"""
from __future__ import annotations
from typing import Any

def _h(headers: dict, key: str):
    """Case-insensitive header lookup"""
    return headers.get(key.lower()) or headers.get(key)


def score_cors(headers: dict) -> dict:
    value = _h(headers, "access-control-allow-origin")
    if not value:
        return {
            "score": 0, "max": 25, "status": "missing",
            "value": None,
            "issue": "No CORS policy set. Cross-origin requests will be blocked or unrestricted.",
            "severity": "high"
        }
    if value == "*":
        return {
            "score": 10, "max": 25, "status": "warn",
            "value": value,
            "issue": "Wildcard (*) allows any origin. Fine for public APIs, risky for authenticated endpoints.",
            "severity": "medium"
        }
    return {
        "score": 25, "max": 25, "status": "pass",
        "value": value,
        "issue": None,
        "severity": None
    }


def score_csp(headers: dict) -> dict:
    value = _h(headers, "content-security-policy")
    if not value:
        return {
            "score": 0, "max": 25, "status": "missing",
            "value": None,
            "issue": "No Content-Security-Policy. XSS attacks have no browser-level mitigation.",
            "severity": "critical"
        }
    
    score = 25
    issues = []
    
    if "unsafe-inline" in value:
        score -= 10
        issues.append("'unsafe-inline' allows inline scripts (XSS risk)")
    if "unsafe-eval" in value:
        score -= 8
        issues.append("'unsafe-eval' allows eval() (XSS risk)")
    if "default-src *" in value or "script-src *" in value:
        score -= 10
        issues.append("Wildcard source allows scripts from any domain")

    score = max(score, 5)
    status = "pass" if score == 25 else ("warn" if score >= 10 else "fail")
    
    return {
        "score": score, "max": 25, "status": status,
        "value": value,
        "issue": "; ".join(issues) if issues else None,
        "severity": "high" if score < 10 else ("medium" if score < 20 else None)
    }


def score_hsts(headers: dict) -> dict:
    value = _h(headers, "strict-transport-security")
    if not value:
        return {
            "score": 0, "max": 20, "status": "missing",
            "value": None,
            "issue": "No HSTS header. Browser may allow HTTP downgrade attacks.",
            "severity": "high"
        }
    
    score = 20
    issues = []
    
    # Check max-age
    import re
    match = re.search(r'max-age=(\d+)', value)
    if match:
        max_age = int(match.group(1))
        if max_age < 31536000:  # < 1 year
            score -= 5
            issues.append(f"max-age={max_age} is less than 1 year (recommended: 31536000)")
    else:
        score -= 10
        issues.append("No max-age directive found")
    
    if "includeSubDomains" not in value:
        score -= 3
        issues.append("Missing includeSubDomains")
    
    score = max(score, 5)
    status = "pass" if score >= 18 else ("warn" if score >= 10 else "fail")
    
    return {
        "score": score, "max": 20, "status": status,
        "value": value,
        "issue": "; ".join(issues) if issues else None,
        "severity": "medium" if issues else None
    }


def score_xframe(headers: dict) -> dict:
    value = _h(headers, "x-frame-options")
    if not value:
        return {
            "score": 0, "max": 10, "status": "missing",
            "value": None,
            "issue": "No X-Frame-Options. Site may be embeddable in iframes (clickjacking risk).",
            "severity": "medium"
        }
    
    val_upper = value.upper()
    if val_upper in ("DENY", "SAMEORIGIN"):
        return {"score": 10, "max": 10, "status": "pass", "value": value, "issue": None, "severity": None}
    
    return {
        "score": 5, "max": 10, "status": "warn",
        "value": value,
        "issue": f"Value '{value}' is non-standard. Use DENY or SAMEORIGIN.",
        "severity": "low"
    }


def score_xcontent(headers: dict) -> dict:
    value = _h(headers, "x-content-type-options")
    if not value:
        return {
            "score": 0, "max": 10, "status": "missing",
            "value": None,
            "issue": "No X-Content-Type-Options. Browser may MIME-sniff responses (injection risk).",
            "severity": "medium"
        }
    if value.lower() == "nosniff":
        return {"score": 10, "max": 10, "status": "pass", "value": value, "issue": None, "severity": None}
    return {
        "score": 5, "max": 10, "status": "warn",
        "value": value,
        "issue": "Value should be 'nosniff'",
        "severity": "low"
    }


def score_referrer(headers: dict) -> dict:
    value = _h(headers, "referrer-policy")
    good_values = {
        "no-referrer", "no-referrer-when-downgrade",
        "strict-origin", "strict-origin-when-cross-origin"
    }
    if not value:
        return {
            "score": 0, "max": 5, "status": "missing",
            "value": None,
            "issue": "No Referrer-Policy. Full URLs may leak in referrer headers.",
            "severity": "low"
        }
    if value.lower() in good_values:
        return {"score": 5, "max": 5, "status": "pass", "value": value, "issue": None, "severity": None}
    return {
        "score": 3, "max": 5, "status": "warn",
        "value": value,
        "issue": f"Policy '{value}' may leak referrer data. Consider strict-origin-when-cross-origin.",
        "severity": "low"
    }


def score_permissions(headers: dict) -> dict:
    value = _h(headers, "permissions-policy")
    if not value:
        return {
            "score": 0, "max": 5, "status": "missing",
            "value": None,
            "issue": "No Permissions-Policy. Browser features (camera, mic, geolocation) not restricted.",
            "severity": "low"
        }
    return {"score": 5, "max": 5, "status": "pass", "value": value, "issue": None, "severity": None}


def analyze_headers(headers: dict) -> dict:
    """Run all checks and return full analysis."""
    # Normalize keys to lowercase
    headers = {k.lower(): v for k, v in headers.items()}
    
    return {
        "cors": score_cors(headers),
        "csp": score_csp(headers),
        "hsts": score_hsts(headers),
        "x_frame_options": score_xframe(headers),
        "x_content_type": score_xcontent(headers),
        "referrer_policy": score_referrer(headers),
        "permissions_policy": score_permissions(headers),
    }