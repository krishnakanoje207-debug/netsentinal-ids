"""The model registry over HTTP, and the promotion gate on it.

The fixtures give a tier with one model deciding and one observing, and a shadow
period the candidate wins. What these tests are about is the gate around it: who
may promote, what the evidence has to show first, and whether the reason for a
refusal survives the trip to the dashboard as something an operator can act on.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from netsentinel_api.db.models import ModelMode
from netsentinel_api.services.shadow import Scored

# Wide enough to contain the whole fixture window, which spans about seven and a
# half days. Tests that want a shortfall ask for a narrow window instead.
WIDE = "30d"


def test_the_registry_says_which_model_is_deciding(client, auth_header):
    response = client.get(f"/api/v1/models?since={WIDE}", headers=auth_header)
    assert response.status_code == 200

    modes = {row["model_id"]: row["mode"] for row in response.json()}
    assert modes == {1: "active", 2: "shadow"}


def test_a_retired_model_is_still_listed(client, auth_header, models):
    models[0].mode = ModelMode.retired

    rows = client.get(f"/api/v1/models?since={WIDE}", headers=auth_header).json()

    # The predecessor is the evidence for the last promotion. Dropping it would
    # leave the question asked after a missed detection - what changed, and when -
    # with nothing on the page to answer it.
    assert [row["model_id"] for row in rows] == [1, 2]
    assert rows[0]["mode"] == "retired"


def test_the_evidence_travels_with_the_model(client, auth_header):
    rows = client.get(f"/api/v1/models?since={WIDE}", headers=auth_header).json()
    candidate = next(row for row in rows if row["model_id"] == 2)

    evidence = candidate["evidence"]
    assert evidence["labelled"] == 60
    assert evidence["true_positives"] == 20
    assert evidence["false_positives"] == 0
    # A model that separates the classes perfectly ranks them perfectly.
    assert evidence["average_precision"] == 1.0


def test_unlabelled_volume_is_served_beside_precision(client, auth_header, scored):
    # One verdict nobody ever triaged. It must be counted and must not flatter the
    # precision that sits next to it on the page.
    scored.append(
        Scored(
            model_id=2,
            risk_score=0.99,
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
            label=None,
        )
    )

    rows = client.get(f"/api/v1/models?since={WIDE}", headers=auth_header).json()
    evidence = next(row for row in rows if row["model_id"] == 2)["evidence"]

    assert evidence["scored"] == 61
    assert evidence["labelled"] == 60
    assert evidence["unlabelled"] == 1
    assert evidence["precision"] == 1.0


def test_a_metric_with_nothing_behind_it_is_null_rather_than_zero(
    client, auth_header, scored
):
    # Every labelled flow closed as a false positive: the window shows the model
    # agreeing about what is harmless and nothing about what it detects.
    scored[:] = [replace(verdict, label=False) for verdict in scored]

    rows = client.get(f"/api/v1/models?since={WIDE}", headers=auth_header).json()
    evidence = next(row for row in rows if row["model_id"] == 2)["evidence"]

    assert evidence["average_precision"] is None
    assert evidence["recall"] is None


def test_a_candidate_that_has_earned_it_says_so(client, auth_header):
    rows = client.get(f"/api/v1/models?since={WIDE}", headers=auth_header).json()

    candidate = next(row for row in rows if row["model_id"] == 2)
    assert candidate["blocked_by"] is None
    # The incumbent is not a candidate at all, and the page has to say why without
    # implying it failed an evidential bar.
    assert next(row for row in rows if row["model_id"] == 1)["blocked_by"] == "already active"


def test_a_window_nobody_can_read_is_refused(client, auth_header):
    response = client.get("/api/v1/models?since=last+tuesday", headers=auth_header)

    assert response.status_code == 422
    assert "last tuesday" in response.json()["detail"]


# --- the gate --------------------------------------------------------------

def test_an_analyst_may_read_the_registry_and_not_promote_from_it(client, auth_header):
    assert client.get(f"/api/v1/models?since={WIDE}", headers=auth_header).status_code == 200

    response = client.post(
        "/api/v1/models/2/promote", headers=auth_header, json={"since": WIDE}
    )

    assert response.status_code == 403
    assert "models:deploy" in response.json()["detail"]


def test_promotion_makes_one_model_decide_and_retires_the_other(
    client, engineer_header, models
):
    response = client.post(
        "/api/v1/models/2/promote", headers=engineer_header, json={"since": WIDE}
    )

    assert response.status_code == 200
    assert response.json()["mode"] == "active"
    assert models[0].mode is ModelMode.retired
    assert models[1].mode is ModelMode.active


def test_the_reply_carries_the_state_the_caller_just_created(client, engineer_header):
    body = client.post(
        "/api/v1/models/2/promote", headers=engineer_header, json={"since": WIDE}
    ).json()

    assert body["mode"] == "active"
    assert body["deployed_at"] is not None
    # No longer a candidate, and the page it returns to has to stop offering it.
    assert body["blocked_by"] == "already active"


def test_the_evidence_is_recorded_with_the_decision(client, engineer_header, session):
    client.post("/api/v1/models/2/promote", headers=engineer_header, json={"since": WIDE})

    entry = next(e for e in session.audit_entries() if e.action == "model.promoted")
    assert entry.entity == "ml_model:2"
    assert entry.details["replaced"] == 1
    # The numbers on the page somebody clicked from, written down permanently.
    assert entry.details["evidence"]["labelled"] == 60
    assert entry.details["evidence"]["average_precision"] == 1.0


def test_a_promotion_names_who_made_it(client, engineer_header, session, ml_engineer):
    client.post("/api/v1/models/2/promote", headers=engineer_header, json={"since": WIDE})

    entry = next(e for e in session.audit_entries() if e.action == "model.promoted")
    assert entry.user_id == ml_engineer.user_id


def test_too_little_evidence_is_refused_with_a_sentence(client, engineer_header, models):
    # A twelve-hour window holds four or five of the fixture's verdicts, which is
    # well under the fifty labelled detections the default bar asks for.
    response = client.post(
        "/api/v1/models/2/promote", headers=engineer_header, json={"since": "12h"}
    )

    assert response.status_code == 422
    assert "labelled detection(s)" in response.json()["detail"]
    # Refused means refused: nothing moved.
    assert models[1].mode is ModelMode.shadow


def test_a_model_that_is_already_deciding_is_not_promoted_again(client, engineer_header):
    response = client.post(
        "/api/v1/models/1/promote", headers=engineer_header, json={"since": WIDE}
    )

    assert response.status_code == 422
    assert "already active" in response.json()["detail"]


def test_a_candidate_that_ranks_worse_than_the_incumbent_is_refused(
    client, engineer_header, scored, models
):
    # Flip the candidate's scores so it ranks the false positives above the true
    # ones. It still has sixty labels over eight days; it is simply worse.
    scored[:] = [
        replace(verdict, risk_score=0.1 if verdict.label else 0.9)
        if verdict.model_id == 2
        else verdict
        for verdict in scored
    ]

    response = client.post(
        "/api/v1/models/2/promote", headers=engineer_header, json={"since": WIDE}
    )

    assert response.status_code == 422
    assert "average precision" in response.json()["detail"]
    assert models[0].mode is ModelMode.active


def test_promoting_a_model_that_does_not_exist_is_a_404(client, engineer_header):
    response = client.post(
        "/api/v1/models/99/promote", headers=engineer_header, json={"since": WIDE}
    )

    assert response.status_code == 404
