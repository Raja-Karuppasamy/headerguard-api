from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import httpx
import asyncio
from typing import Optional
from scorer import analyze_headers
from fixgen import generate_fixes

app = FastAPI(
    title="HeaderGuard API",
    description="HTTP Security Header Analyzer & Fixer",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    stack: Optional[str] = None  # fastapi | express | django | nginx | caddy

class ScanResponse(BaseModel):
    url: str
    score: int
    grade: str
    summary: str
    headers: dict
    fixes: dict
    raw_headers: dict

def get_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"

@app.get("/")
async def root():
    return {"service": "HeaderGuard API", "version": "1.0.0", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    url = req.url
    if not url.startswith("http"):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
            raw_headers = dict(response.headers)
    except httpx.TimeoutException:
        raise HTTPException(status_code=408, detail="Target URL timed out")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not reach URL: {str(e)}")

    analysis = analyze_headers(raw_headers)
    fixes = generate_fixes(analysis, stack=req.stack)
    total_score = sum(h["score"] for h in analysis.values())
    grade = get_grade(total_score)

    issues = [k for k, v in analysis.items() if v["status"] != "pass"]
    if total_score >= 80:
        summary = "Strong security posture. Minor improvements possible."
    elif total_score >= 60:
        summary = f"{len(issues)} header(s) need attention."
    else:
        summary = f"Critical: {len(issues)} security headers missing or misconfigured."

    return ScanResponse(
        url=url,
        score=total_score,
        grade=grade,
        summary=summary,
        headers=analysis,
        fixes=fixes,
        raw_headers={k: v for k, v in raw_headers.items() if k.lower() in [
            "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options",
            "access-control-allow-origin", "referrer-policy",
            "permissions-policy", "x-xss-protection"
        ]}
    )