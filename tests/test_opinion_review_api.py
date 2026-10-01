from __future__ import annotations


def _login(client, username: str, password: str) -> dict:
    response = client.post("/api/auth/login", json={
        "username": username, "password": password, "client_label": "tests",
    })
    assert response.status_code == 200, response.text
    body = response.json()
    return {"token": body["token"], "headers": {"Authorization": f"Bearer {body['token']}"}}


def _make_user(client, admin, username: str, role: str) -> dict:
    response = client.post("/api/users", headers=admin["headers"], json={
        "username": username, "password": "Review!23456", "display_name": username, "role_codes": [role],
    })
    assert response.status_code == 201, response.text
    return _login(client, username, "Review!23456")


def _completed_examination(client, admin, suffix: str = "H1") -> tuple[int, int, int]:
    headers = admin["headers"]
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": f"{suffix}-ORG", "agency_name": "委托机构", "jurisdiction_code": "CN",
        "contact_address": "司法路", "restrictions": {},
    }).json()
    case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": f"{suffix}-CASE", "case_name": "鉴定案件", "discipline": "法医物证",
        "entrusted_matter": "检验", "agency_id": agency["id"], "case_source": "委托",
        "accepted_on": "2026-09-01", "passport": {}, "created_by": "登记员",
    }).json()
    client.post(f"/api/forensics/cases/{case['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "齐全", "expected_version": 1, "actor": "审核员",
    })
    location = client.post("/api/forensics/locations", headers=headers, json={
        "location_code": f"{suffix}-V", "facility": "库", "room": "室", "rack": "R", "shelf": "S",
        "capacity_units": 100, "reference_value": 4, "humidity_percent": 45,
    }).json()
    specimen = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": f"{suffix}-SP", "case_id": case["id"], "received_year": 2026,
        "initial_quantity": 10, "integrity_percent": 100, "packaging": "封", "created_by": "登记员",
    }).json()
    client.post("/api/forensics/placements", headers=headers, json={
        "specimen_id": specimen["id"], "location_id": location["id"], "quantity": 10,
        "container_code": f"{suffix}-BOX", "idempotency_key": f"{suffix}-place", "actor": "保管员",
    })
    protocol = client.post("/api/forensics/protocols", headers=headers, json={
        "protocol_code": f"{suffix}-DNA", "discipline": "法医物证", "observation_target": 100,
        "checkpoint_count": 1, "reference_value": 0.99, "turnaround_days": 14,
        "conclusion_rule": "位点质量满足复核阈值", "created_by": "负责人",
    }).json()
    exam = client.post("/api/forensics/examinations", headers=headers, json={
        "examination_no": f"{suffix}-EX", "specimen_id": specimen["id"], "protocol_id": protocol["id"],
        "examination_type": "补充检验", "sample_quantity": 1, "scheduled_for": "2026-09-20",
        "requested_by": "检验员", "idempotency_key": f"{suffix}-sched",
    }).json()
    client.post(f"/api/forensics/examinations/{exam['id']}/start", headers=headers, json={
        "performed_by": "鉴定人甲", "expected_version": 1,
    })
    observation = client.post(f"/api/forensics/examinations/{exam['id']}/observations", headers=headers, json={
        "checkpoint_no": 1, "items_checked": 100, "conforming_count": 96,
        "exception_count": 4, "unusable_count": 0, "pending_count": 0,
        "sequence_no": 1, "observed_by": "鉴定人甲",
    }).json()
    client.post(f"/api/forensics/examinations/{exam['id']}/complete", headers=headers, json={
        "performed_by": "鉴定人甲", "expected_version": 2,
    })
    return case["id"], exam["id"], specimen["id"], observation["id"]


def test_opinion_review_role_separation_and_timeline(client, admin):
    technician = _make_user(client, admin, "tech.jia", "technician")
    curator = _make_user(client, admin, "curator.yi", "curator")
    officer = _make_user(client, admin, "officer.zhibing", "quality_officer")

    case_id, exam_id, specimen_id, observation_id = _completed_examination(client, admin)

    # 复核人资质登记仅质量负责人可操作
    denied = client.post("/api/forensics/reviewers", headers=curator["headers"], json={
        "reviewer": "curator.yi", "discipline": "法医物证", "note": "", "actor": "质量负责人",
    })
    assert denied.status_code == 403
    registered = client.post("/api/forensics/reviewers", headers=officer["headers"], json={
        "reviewer": "curator.yi", "discipline": "法医物证", "note": "持证复核", "actor": "officer.zhibing",
    })
    assert registered.status_code == 201, registered.text

    # 鉴定人提交不可覆盖版本
    created = client.post("/api/forensics/opinions", headers=technician["headers"], json={
        "opinion_no": "HOP-1", "case_id": case_id, "examination_id": exam_id, "title": "鉴定意见书",
        "body": "鉴定结论正文", "cited_specimen_ids": [specimen_id], "cited_observation_ids": [observation_id],
        "declaration_note": "所引检材、观察记录和方法版本真实有效", "deadline_hours": 72, "actor": "鉴定人甲",
    })
    assert created.status_code == 201, created.text
    opinion_id = created.json()["id"]

    # 鉴定人没有复核权限，不能领取（角色层 403；同一人回避由服务层测试覆盖）
    self_claim = client.post(f"/api/forensics/opinions/{opinion_id}/claim", headers=technician["headers"],
                             json={"reviewer": "鉴定人甲"})
    assert self_claim.status_code == 403
    # 复核人角色不能签发
    forbidden_issue = client.post(f"/api/forensics/opinions/{opinion_id}/issue", headers=curator["headers"], json={
        "actor": "curator.yi", "note": "x", "expected_version": 1,
    })
    assert forbidden_issue.status_code == 403
    # 质量负责人不能起草意见
    forbidden_create = client.post("/api/forensics/opinions", headers=officer["headers"], json={
        "opinion_no": "HOP-X", "case_id": case_id, "examination_id": exam_id, "title": "越权意见",
        "body": "x", "cited_specimen_ids": [], "cited_observation_ids": [],
        "deadline_hours": 72, "actor": "officer.zhibing",
    })
    assert forbidden_create.status_code == 403

    # 复核人领取并提出带定位与严重程度的阻断问题
    claim = client.post(f"/api/forensics/opinions/{opinion_id}/claim", headers=curator["headers"],
                        json={"reviewer": "curator.yi"})
    assert claim.status_code == 200, claim.text
    duplicate = client.post(f"/api/forensics/opinions/{opinion_id}/claim", headers=officer["headers"],
                            json={"reviewer": "officer.zhibing"})
    assert duplicate.status_code == 409

    finding = client.post(f"/api/forensics/opinions/{opinion_id}/findings", headers=curator["headers"], json={
        "reviewer": "curator.yi", "location": "第3页数据表第2行", "severity": "blocking",
        "description": "计数与观察记录不符",
    })
    assert finding.status_code == 201, finding.text
    finding_id = finding.json()["id"]

    returned = client.post(f"/api/forensics/opinions/{opinion_id}/review-decision", headers=curator["headers"], json={
        "approve": False, "note": "请核对数据", "reviewer": "curator.yi",
    })
    assert returned.status_code == 200
    assert returned.json()["status"] == "revision"

    # 退修形成新版本
    revision = client.post(f"/api/forensics/opinions/{opinion_id}/revisions", headers=technician["headers"], json={
        "body": "鉴定结论正文（已核对）", "cited_specimen_ids": [specimen_id],
        "cited_observation_ids": [observation_id],
        "declaration_note": "声明", "change_note": "更正数据表", "actor": "鉴定人甲",
    })
    assert revision.status_code == 201, revision.text
    bodies = [item["body"] for item in revision.json()["versions"]]
    assert bodies == ["鉴定结论正文", "鉴定结论正文（已核对）"]

    # 逐条处理并经复核人确认
    respond = client.post(f"/api/forensics/findings/{finding_id}/response", headers=technician["headers"], json={
        "note": "已按观察记录更正", "accept": True, "actor": "鉴定人甲",
    })
    assert respond.status_code == 200, respond.text
    resubmit = client.post(f"/api/forensics/opinions/{opinion_id}/resubmit", headers=technician["headers"], json={
        "change_note": "修改完成", "deadline_hours": 72, "actor": "鉴定人甲",
    })
    assert resubmit.status_code == 200, resubmit.text
    client.post(f"/api/forensics/opinions/{opinion_id}/claim", headers=curator["headers"],
                json={"reviewer": "curator.yi"})
    confirm = client.post(f"/api/forensics/findings/{finding_id}/confirm", headers=curator["headers"], json={
        "note": "复核确认", "accept": True, "actor": "curator.yi",
    })
    assert confirm.status_code == 200, confirm.text

    # 阻断意见未关闭时签发应失败——这里已关闭，先验复核通过
    approved = client.post(f"/api/forensics/opinions/{opinion_id}/review-decision", headers=curator["headers"], json={
        "approve": True, "note": "通过", "reviewer": "curator.yi",
    })
    assert approved.status_code == 200
    approved_body = approved.json()
    assert approved_body["status"] == "approved"

    # 鉴定人不能签发
    technician_issue = client.post(f"/api/forensics/opinions/{opinion_id}/issue", headers=technician["headers"], json={
        "actor": "鉴定人甲", "note": "签发", "expected_version": approved_body["version"],
    })
    assert technician_issue.status_code == 403

    issued = client.post(f"/api/forensics/opinions/{opinion_id}/issue", headers=officer["headers"], json={
        "actor": "officer.zhibing", "note": "准予签发", "expected_version": approved_body["version"],
    })
    assert issued.status_code == 200, issued.text
    assert issued.json()["status"] == "issued"

    # 时间线还原：版本、领取、退修、复核、签发齐全，且签发版本等于复核通过版本
    timeline = client.get(f"/api/forensics/opinions/{opinion_id}/timeline", headers=officer["headers"])
    assert timeline.status_code == 200
    body = timeline.json()
    event_types = {event["event_type"] for event in body["events"]}
    assert {"created", "version_submitted", "review_pooled", "claimed", "finding_raised",
            "review_returned", "finding_responded", "review_approved", "issued"} <= event_types
    proof = body["issuance_proof"]
    assert proof["version_match"] is True
    assert proof["hash_match"] is True
    assert proof["recomputed_hash_match"] is True

    # 无 opinion.read 权限的角色不能查询时间线
    fresh = _make_user(client, admin, "clerk.noread", "registrar")
    forbidden_timeline = client.get(f"/api/forensics/opinions/{opinion_id}/timeline",
                                    headers=fresh["headers"])
    assert forbidden_timeline.status_code == 403
