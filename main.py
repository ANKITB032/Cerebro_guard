from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, field_validator
import logging
import os

from analyzer import PhishingAnalyzer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="CerebroGuard", version="2.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

# Load analyzer once at startup (non-blocking for graph)
analyzer = PhishingAnalyzer(
    graph_path=os.getenv("GRAPH_PATH", "data/enron_graph.graphml")
)


class EmailPayload(BaseModel):
    sender: str
    recipient: str
    subject: str = ""
    body: str = ""
    cc: list[str] = []

    @field_validator("body")
    @classmethod
    def body_max_length(cls, v):
        if len(v) > 20_000:
            raise ValueError("Body exceeds 20,000 character limit")
        return v

    @field_validator("sender", "recipient")
    @classmethod
    def email_not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Email address cannot be empty")
        return v


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze")
@limiter.limit("30/minute")
async def analyze(payload: EmailPayload, request: Request):
    try:
        logger.info(f"Analyzing email from {payload.sender} to {payload.recipient}")
        result = analyzer.analyze(
            sender=payload.sender,
            recipient=payload.recipient,
            subject=payload.subject,
            body=payload.body,
            cc=payload.cc,
        )
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "graph_loaded": analyzer.graph_loaded,
        "nlp_loaded": analyzer.nlp_loaded,
    }
