"""Glue between the API and the NLP pipeline: background processing + small in-memory caches."""
import threading
import traceback
from functools import lru_cache

import pandas as pd

from db import database as db
from nlp import unit1_preprocess_lm as u1
from nlp import unit3_dependency_semantics as u3
from nlp import unit4_tfidf_ie as u4
from nlp.load_data import read_alert_file, to_dataframe
from nlp.pipeline import run_pipeline

_pipeline_lock = threading.Lock()  # spaCy model is shared: run one analysis at a time


def process_analysis(analysis_id, raw):
    """Runs in a FastAPI BackgroundTask. Status ends as 'done' or 'failed' in the analyses table."""
    try:
        with _pipeline_lock:
            df = to_dataframe(read_alert_file(raw))
            res = run_pipeline(df, log=lambda m: print(f"[analysis {analysis_id}] {m}"))
            db.save_results(analysis_id, res)
    except ValueError as e:  # bad input file (empty, not JSON, missing fields): a clear message, no traceback
        print(f"[analysis {analysis_id}] rejected input: {e}")
        db.mark_failed(analysis_id, f"{type(e).__name__}: {e}")
    except Exception as e:  # noqa: BLE001 - unexpected bug: record it and keep the traceback for debugging
        traceback.print_exc()
        db.mark_failed(analysis_id, f"{type(e).__name__}: {e}")


def alerts_frame(analysis_id):
    df = pd.DataFrame(db.get_alerts(analysis_id))
    if len(df):
        df = df.astype(object).where(df.notna(), None)   # NULL -> None (not NaN)
        df["level"] = df["level"].astype(int)
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601")
    return df


@lru_cache(maxsize=4)
def corpus_context(analysis_id):
    """Models rebuilt from a stored analysis for the NLP Lab and Q&A (cached per analysis).
    Rebuilding is cheap (seconds) and avoids pickling models into the database."""
    df = alerts_frame(analysis_id)
    sentences = list(df["sentence"])
    lm, stats, token_lists = u1.train_and_evaluate_lm(sentences)
    vec, _ = u4.build_tfidf(list(dict.fromkeys(u4.feature_text(s) for s in sentences)))
    vocab, M = u3.cooccurrence_vectors(token_lists[:20000])
    from sklearn.feature_extraction.text import TfidfVectorizer
    qa_vec = TfidfVectorizer(token_pattern=r"[a-z0-9][a-z0-9_\-.]+", sublinear_tf=True)
    qa_X = qa_vec.fit_transform([s.lower() for s in sentences])
    return {"df": df, "lm": lm, "lm_stats": stats, "tfidf": vec, "vocab": vocab, "vectors": u4.ppmi_matrix(M),
            "qa": (qa_vec, qa_X)}


def forget(analysis_id):
    corpus_context.cache_clear()
