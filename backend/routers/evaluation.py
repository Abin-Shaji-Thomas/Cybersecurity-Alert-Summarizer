"""/api/evaluation - results produced by `python -m nlp.evaluate` (data/eval/results.json)."""
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])
RESULTS = Path(__file__).resolve().parents[2] / "data" / "eval" / "results.json"


@router.get("")
def evaluation():
    if not RESULTS.exists():
        raise HTTPException(404, "No evaluation results yet. Run: cd backend; .venv\\Scripts\\python -m nlp.evaluate")
    return json.loads(RESULTS.read_text(encoding="utf-8"))
