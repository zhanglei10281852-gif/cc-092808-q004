from __future__ import annotations

PASSWORD = "Passw0rd!23"


def _login(client, username: str) -> dict:
    response = client.post("/api/auth/login", json={
        "username": username, "password": PASSWORD, "client_label": "api-test",
    })
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}}


def _create_user(client, admin_headers: dict, username: str, display: str, role: str) -> dict:
    response = client.post("/api/users", headers=admin_headers, json={
        "username": username, "password": PASSWORD, "display_name": display, "role_codes": [role],
    })
    assert response.status_code == 201, response.text
    return response.json()


def _prepare_completed_examination(client, headers: dict) -> dict:
    source = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": "API-OP-ORG", "agency_name": "区公安分局", "jurisdiction_code": "CN",
        "contact_address": "司法路 12 号", "restrictions": {},
    })
    assert source.status_code == 201, source.text
    case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": "API-OP-CASE", "case_name": "生物物证鉴定", "discipline": "法医物证",
        "entrusted_matter": "同一性比对", "agency_id": source.json()["id"], "case_source": "委托",
        "accepted_on": "2026-09-20", "passport": {}, "created_by": "登记员",
    })
    assert case.status_code == 201, case.text
    accepted = client.post(f"/api/forensics/cases/{case.json()['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "手续齐全", "expected_version": 1, "actor": "审核员",
    })
    assert accepted.status_code == 200, accepted.text
    location = client.post("/api/forensics/locations", headers=headers, json={
        "location_code": "API-OP-V", "facility": "保管室", "room": "冷藏区", "rack": "R1", "shelf": "S1",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    assert location.status_code == 201, location.text
    specimen = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "API-OP-SP", "case_id": case.json()["id"], "received_year": 2026,
        "initial_quantity": 100, "integrity_percent": 100, "packaging": "独立封装", "created_by": "登记员",
    })
    assert specimen.status_code == 201, specimen.text
    placement = client.post("/api/forensics/placements", headers=headers, json={
        "specimen_id": specimen.json()["id"], "location_id": location.json()["id"], "quantity": 100,
        "container_code": "API-OP-BOX", "idempotency_key": "api-op-place-1", "actor": "保管员",
    })
    assert placement.status_code == 201, placement.text
    protocol = client.post("/api/forensics/protocols", headers=headers, json={
        "protocol_code": "API-OP-METHOD", "discipline": "法医物证", "observation_target": 100,
        "checkpoint_count": 1, "reference_value": 0.99, "turnaround_days": 14,
        "conclusion_rule": "位点质量满足阈值", "created_by": "技术负责人",
    })
    assert protocol.status_code == 201, protocol.text
    examination = client.post("/api/forensics/examinations", headers=headers, json={
        "examination_no": "API-OP-EX", "specimen_id": specimen.json()["id"],
        "protocol_id": protocol.json()["id"], "examination_type": "补充检验", "sample_quantity": 5,
        "scheduled_for": "2026-09-25", "requested_by": "鉴定人甲", "idempotency_key": "api-op-sched-1",
    })
    assert examination.status_code == 201, examination.text
    exam_id = examination.json()["id"]
    started = client.post(f"/api/forensics/examinations/{exam_id}/start", headers=headers, json={
        "performed_by": "鉴定人甲", "expected_version": 1,
    })
    assert started.status_code == 200, started.text
    observation = client.post(f"/api/forensics/examinations/{exam_id}/observations", headers=headers, json={
        "checkpoint_no": 1, "items_checked": 100, "conforming_count": 95, "exception_count": 3,
        "unusable_count": 2, "pending_count": 0, "sequence_no": 14, "observed_by": "鉴定人甲",
    })
    assert observation.status_code == 201, observation.text
    completed = client.post(f"/api/forensics/examinations/{exam_id}/complete", headers=headers, json={
        "performed_by": "鉴定人甲", "expected_version": 2,
    })
    assert completed.status_code == 200, completed.text
    return {
        "case_id": case.json()["id"], "exam_id": exam_id,
        "specimen_id": specimen.json()["id"], "protocol_id": protocol.json()["id"],
        "observation_id": observation.json()["id"],
    }


SECTIONS_V1 = {
    "基本情况": "委托与检材基本情况记载完整。",
    "检验过程": "依据规程对检材进行检验。",
    "鉴定意见": "检见特征与样本符合，倾向同一。",
}


def test_opinion_review_issue_api_timeline(client, admin):
    admin_h = admin["headers"]
    _create_user(client, admin_h, "apiexpert", "鉴定人甲", "technician")
    _create_user(client, admin_h, "apireviewer", "复核人甲", "curator")
    _create_user(client, admin_h, "apireviewer2", "复核人乙", "curator")
    _create_user(client, admin_h, "apiquality", "质量负责人", "quality_manager")
    expert = _login(client, "apiexpert")
    reviewer = _login(client, "apireviewer")
    reviewer2 = _login(client, "apireviewer2")
    quality = _login(client, "apiquality")

    bundle = _prepare_completed_examination(client, admin["headers"])

    # ---- 鉴定人创建意见并提交不可覆盖版本（声明引用） ----
    created = client.post("/api/forensics/opinions", headers=expert["headers"], json={
        "opinion_no": "API-OPINION-1", "case_id": bundle["case_id"],
        "examination_id": bundle["exam_id"], "title": "同一性鉴定意见",
    })
    assert created.status_code == 201, created.text
    opinion_id = created.json()["id"]

    submit_url = f"/api/forensics/opinions/{opinion_id}/versions"
    submitted = client.post(submit_url, headers=expert["headers"], json={
        "sections": SECTIONS_V1,
        "references": [
            {"ref_type": "specimen", "ref_id": bundle["specimen_id"], "ref_label": "血痕检材"},
            {"ref_type": "observation", "ref_id": bundle["observation_id"], "ref_label": "检查点1"},
            {"ref_type": "protocol", "ref_id": bundle["protocol_id"], "ref_label": "检验规程"},
        ],
        "change_summary": "首次提交", "responses": [],
    })
    assert submitted.status_code == 201, submitted.text
    assert submitted.json()["status"] == "pending_review"

    # ---- 鉴定人不能复核自己的意见（无复核权限，且同一人回避） ----
    pool_for_expert = client.get("/api/forensics/review-tasks/pending", headers=expert["headers"])
    assert pool_for_expert.status_code == 403

    pool = client.get("/api/forensics/review-tasks/pending", headers=reviewer["headers"])
    assert pool.status_code == 200
    task_id = pool.json()[0]["id"]

    # ---- 并发领取：两个复核人同时领取，只能成功一次 ----
    first = client.post(f"/api/forensics/review-tasks/{task_id}/claim", headers=reviewer["headers"])
    second = client.post(f"/api/forensics/review-tasks/{task_id}/claim", headers=reviewer2["headers"])
    assert first.status_code == 201, first.text
    assert second.status_code == 409

    # ---- 提出带定位、严重程度的阻断问题并退修 ----
    finding = client.post(f"/api/forensics/review-tasks/{task_id}/findings", headers=reviewer["headers"], json={
        "location_ref": "鉴定意见", "severity": "critical", "handling": "must_revise",
        "description": "结论超出检验结果支持范围",
    })
    assert finding.status_code == 201, finding.text
    finding_id = finding.json()["id"]
    returned = client.post(f"/api/forensics/review-tasks/{task_id}/decision", headers=reviewer["headers"], json={
        "approve": False, "summary": "结论需收敛",
        "confirmed_sections": ["基本情况", "检验过程"], "resolutions": [],
    })
    assert returned.status_code == 200, returned.text

    # ---- 退修新版本：逐条回应；已确认章节逐字保留 ----
    sections_v2 = dict(SECTIONS_V1)
    sections_v2["鉴定意见"] = "出具限定条件下的同一性意见。"
    resubmit = client.post(submit_url, headers=expert["headers"], json={
        "sections": sections_v2,
        "references": [
            {"ref_type": "specimen", "ref_id": bundle["specimen_id"], "ref_label": "血痕检材"},
            {"ref_type": "observation", "ref_id": bundle["observation_id"], "ref_label": "检查点1"},
            {"ref_type": "protocol", "ref_id": bundle["protocol_id"], "ref_label": "检验规程"},
        ],
        "change_summary": "按阻断意见收敛结论",
        "responses": [{"finding_id": finding_id, "response_text": "已删除超出检验支持的表述"}],
    })
    assert resubmit.status_code == 201, resubmit.text

    pool2 = client.get("/api/forensics/review-tasks/pending", headers=reviewer2["headers"])
    task2_id = pool2.json()[0]["id"]
    claim2 = client.post(f"/api/forensics/review-tasks/{task2_id}/claim", headers=reviewer2["headers"])
    assert claim2.status_code == 201, claim2.text
    resolved = client.post(f"/api/forensics/findings/{finding_id}/resolve", headers=reviewer2["headers"], json={
        "status": "resolved", "note": "新版本已按要求修改",
    })
    assert resolved.status_code == 200, resolved.text
    approved = client.post(f"/api/forensics/review-tasks/{task2_id}/decision", headers=reviewer2["headers"], json={
        "approve": True, "summary": "阻断意见已全部关闭", "confirmed_sections": [], "resolutions": [],
    })
    assert approved.status_code == 200, approved.text

    # ---- 未关闭阻断意见校验已通过；质量负责人签发 ----
    issued = client.post(f"/api/forensics/opinions/{opinion_id}/issue", headers=quality["headers"])
    assert issued.status_code == 200, issued.text
    body = issued.json()
    assert body["status"] == "issued"
    assert body["issued_version_id"] == body["approved_version_id"]

    # ---- 通过 API 还原完整时间线，并证明签发依据复核通过的确切版本 ----
    timeline = client.get(f"/api/forensics/opinions/{opinion_id}/timeline", headers=reviewer["headers"])
    assert timeline.status_code == 200, timeline.text
    data = timeline.json()
    types = [event["type"] for event in data["events"]]
    for expected in ("version", "claim", "finding", "review", "revision_response", "finding_closed", "issued"):
        assert expected in types, types
    assert types.count("version") == 2
    proof = data["issuance_proof"]
    assert proof["approved_version_matches_issued"] is True
    assert proof["issued_version_no"] == 2
    assert proof["approval"]["reviewer_name"] == "复核人乙"
    assert {ref["current_status"] for ref in proof["references"]} == {"valid"}


def test_opinion_endpoints_require_authentication(client):
    assert client.get("/api/forensics/review-tasks/pending").status_code == 401
    assert client.get("/api/forensics/opinions/1/timeline").status_code == 401
