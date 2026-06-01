from __future__ import annotations
"""
HeaderGuard Fix Generator
Generates stack-specific code snippets to fix missing/misconfigured headers.
Supported stacks: fastapi, express, django, nginx, caddy (default: generic)
"""

FIXES = {
    "cors": {
        "fastapi": '''# Add to your FastAPI app
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Replace with your origin
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)''',
        "express": '''// Add to your Express app
const cors = require('cors');

app.use(cors({
  origin: 'https://yourdomain.com',  // Replace with your origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));''',
        "django": '''# In settings.py
INSTALLED_APPS = [..., 'corsheaders']
MIDDLEWARE = ['corsheaders.middleware.CorsMiddleware', ...]

CORS_ALLOWED_ORIGINS = [
    "https://yourdomain.com",
]
CORS_ALLOW_CREDENTIALS = True''',
        "nginx": '''# In your nginx server block
add_header 'Access-Control-Allow-Origin' 'https://yourdomain.com';
add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization';''',
        "caddy": '''# In your Caddyfile
header {
    Access-Control-Allow-Origin "https://yourdomain.com"
    Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Access-Control-Allow-Headers "Content-Type, Authorization"
}''',
        "generic": "Set the 'Access-Control-Allow-Origin' response header to your allowed origin(s). Avoid using '*' for authenticated endpoints."
    },

    "csp": {
        "fastapi": '''# Add CSP middleware to FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response

app.add_middleware(CSPMiddleware)''',
        "express": '''// Add to Express app
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none';"
  );
  next();
});''',
        "nginx": '''# In nginx server block
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none';";''',
        "caddy": '''header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none';"''',
        "generic": "Add 'Content-Security-Policy' header. Start with: default-src 'self'; script-src 'self'; frame-ancestors 'none';"
    },

    "hsts": {
        "fastapi": '''# Add HSTS to FastAPI
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class HSTSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        return response

app.add_middleware(HSTSMiddleware)''',
        "express": '''app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});''',
        "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "caddy": 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        "generic": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
    },

    "x_frame_options": {
        "fastapi": '''response.headers["X-Frame-Options"] = "DENY"''',
        "express": '''res.setHeader('X-Frame-Options', 'DENY');''',
        "nginx": '''add_header X-Frame-Options "DENY" always;''',
        "caddy": '''header X-Frame-Options "DENY"''',
        "generic": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'"
    },

    "x_content_type": {
        "fastapi": '''response.headers["X-Content-Type-Options"] = "nosniff"''',
        "express": '''res.setHeader('X-Content-Type-Options', 'nosniff');''',
        "nginx": '''add_header X-Content-Type-Options "nosniff" always;''',
        "caddy": '''header X-Content-Type-Options "nosniff"''',
        "generic": "Set 'X-Content-Type-Options: nosniff'"
    },

    "referrer_policy": {
        "fastapi": '''response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"''',
        "express": '''res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');''',
        "nginx": '''add_header Referrer-Policy "strict-origin-when-cross-origin" always;''',
        "caddy": '''header Referrer-Policy "strict-origin-when-cross-origin"''',
        "generic": "Set 'Referrer-Policy: strict-origin-when-cross-origin'"
    },

    "permissions_policy": {
        "fastapi": '''response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"''',
        "express": '''res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');''',
        "nginx": '''add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;''',
        "caddy": '''header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"''',
        "generic": "Set 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'"
    }
}


def generate_fixes(analysis: dict, stack: str | None = None) -> dict:
    """Return fix snippets only for failing/warning headers."""
    stack = (stack or "generic").lower()
    if stack not in ("fastapi", "express", "django", "nginx", "caddy"):
        stack = "generic"

    fixes = {}
    for header_key, result in analysis.items():
        if result["status"] != "pass":
            header_fixes = FIXES.get(header_key, {})
            fixes[header_key] = {
                "stack": stack,
                "snippet": header_fixes.get(stack) or header_fixes.get("generic", "No fix available"),
                "docs": f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_key.replace('_', '-')}"
            }

    return fixes