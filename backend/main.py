"""FastAPI entry point.  Run from the backend folder:
    .venv\\Scripts\\uvicorn main:app --reload --port 8000
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from db.database import init_db
from routers import analyses, evaluation, incidents, lab

app = FastAPI(title="Cybersecurity Alert Summarizer", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    # Clear JSON instead of a bare 500 page
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(exc).__name__}: {exc}"})


@app.get("/api/health")
def health():
    return {"status": "ok"}


app.include_router(analyses.router)
app.include_router(incidents.router)
app.include_router(lab.router)
app.include_router(evaluation.router)
