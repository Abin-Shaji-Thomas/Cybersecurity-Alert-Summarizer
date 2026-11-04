"""API smoke test: analyse the bundled sample and call every endpoint (uses a temporary database)."""
import os
import tempfile

import pytest

os.environ["ALERT_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")   # before the app is imported

from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def analysis_id(client):
    r = client.post("/api/analyses/sample")       # TestClient runs the background task before returning
    assert r.status_code == 200
    aid = r.json()["id"]
    a = client.get(f"/api/analyses/{aid}").json()
    assert a["status"] == "done", a.get("error")
    return aid


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_analysis_and_incidents(client, analysis_id):
    a = client.get(f"/api/analyses/{analysis_id}").json()
    assert a["n_alerts"] > 1000 and a["n_incidents"] > 0
    assert any(x["id"] == analysis_id for x in client.get("/api/analyses").json())
    incs = client.get(f"/api/analyses/{analysis_id}/incidents").json()
    assert len(incs) == a["n_incidents"]
    inc = client.get(f"/api/incidents/{incs[0]['id']}").json()
    assert inc["summary_template"] and inc["summary_extractive"] and inc["alerts"] and inc["srl"]
    pdf = client.get(f"/api/incidents/{incs[0]['id']}/pdf")
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"


def test_timeline_entities_insights(client, analysis_id):
    tl = client.get(f"/api/analyses/{analysis_id}/timeline").json()
    assert tl["series"] and tl["events"]
    ents = client.get(f"/api/analyses/{analysis_id}/entities").json()
    assert "IP" in ents["labels"] and ents["relations"]
    ins = client.get(f"/api/analyses/{analysis_id}/insights").json()
    assert ins["unit1"]["lm"]["perplexity_test_smoothed"] > 0 and ins["unit4"]["word_pca"]


def test_ask(client, analysis_id):
    r = client.post(f"/api/analyses/{analysis_id}/ask", json={"question": "Which hosts did 172.19.131.174 attack?"}).json()
    assert "intranet-server" in r["answer"] and r["supporting_alerts"]
    assert client.get(f"/api/analyses/{analysis_id}/qa").json()[-1]["question"].startswith("Which hosts")
    assert client.post(f"/api/analyses/{analysis_id}/ask", json={"question": " "}).status_code == 400


def test_lab(client):
    r = client.post("/api/lab/process", json={"text": "At 03:57:25, host intranet-server reported 'Web server 400 error code' "
                                                      "from 172.19.131.174 targeting port 80 (level 5)."}).json()
    for unit in ("unit1", "unit2", "unit3", "unit4", "unit5"):
        assert unit in r
    assert r["unit2"]["cky"]["parsed"]


def test_errors_and_delete(client, analysis_id):
    assert client.get("/api/analyses/99999").status_code == 404
    bad = client.post("/api/analyses", files={"file": ("x.txt", b"hello", "text/plain")})
    assert bad.status_code == 400
    assert client.delete(f"/api/analyses/{analysis_id}").status_code == 200
    assert client.get(f"/api/analyses/{analysis_id}").status_code == 404
