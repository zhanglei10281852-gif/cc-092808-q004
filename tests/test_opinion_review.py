from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.clock import FrozenClock
from app.core.errors import ConflictError, PermissionDeniedError, ValidationError
from app.database import get_connection, transaction
from app.forensics.service import ForensicService


def _build_completed_examination(service: ForensicService, *, suffix: str = "1", performer: str = "鉴定人甲",
                                 discipline: str = "法医物证", conforming: int = 95) -> tuple[int, int, int, int]:
    agency = service.forensic_cases.create_agency({
        "agency_code": f"ORG-{suffix}", "agency_name": "委托机构", "jurisdiction_code": "CN",
        "contact_address": "司法路", "licensed_on": "2025-01-01", "accreditation_no": None, "restrictions": {},
    })
    case = service.forensic_cases.create_forensic_case({
        "case_no": f"CASE-{suffix}", "case_name": "鉴定案件", "discipline": discipline,
        "entrusted_matter": "检验事项", "agency_id": agency["id"], "case_source": "委托",
        "accepted_on": "2026-09-01", "passport": {}, "created_by": "登记员",
    })
    case = service.forensic_cases.transition(case["id"], {
        "target_status": "accepted", "reason": "齐全", "expected_version": 1, "actor": "审核员",
    })
    location = service.custody.create_location({
        "location_code": f"V-{suffix}", "facility": "库", "room": "室", "rack": "R", "shelf": "S",
        "capacity_units": 100, "reference_value": 4, "humidity_percent": 45,
    })
    specimen = service.custody.create_specimen({
        "specimen_no": f"SP-{suffix}", "case_id": case["id"], "parent_specimen_id": None,
        "received_year": 2026, "initial_quantity": 10, "integrity_percent": 100,
        "packaging": "封识完整", "sealed_on": "2026-09-02", "created_by": "登记员",
    })
    service.custody.place_specimen({
        "specimen_id": specimen["id"], "location_id": location["id"], "quantity": 10,
        "container_code": f"B-{suffix}", "idempotency_key": f"place-{suffix}", "actor": "保管员",
    })
    protocol = service.examinations.create_protocol({
        "protocol_code": f"DNA-{suffix}", "discipline": discipline, "observation_target": 100,
        "checkpoint_count": 1, "reference_value": 0.99, "turnaround_days": 14,
        "conclusion_rule": "阈值规则", "created_by": "技术负责人",
    })
    examination = service.examinations.schedule_examination({
        "examination_no": f"EX-{suffix}", "specimen_id": specimen["id"], "protocol_id": protocol["id"],
        "examination_type": "补充检验", "sample_quantity": 1, "scheduled_for": "2026-09-20",
        "requested_by": "检验员", "idempotency_key": f"sched-{suffix}",
    })
    service.examinations.start_examination(examination["id"], {"performed_by": performer, "expected_version": 1})
    observation = service.examinations.add_observation(examination["id"], {
        "checkpoint_no": 1, "items_checked": 100, "conforming_count": conforming,
        "exception_count": 100 - conforming, "unusable_count": 0, "pending_count": 0,
        "sequence_no": 1, "observed_by": performer,
    })
    completed = service.examinations.complete_examination(
        examination["id"], {"performed_by": performer, "expected_version": 2}
    )
    return case["id"], completed["id"], specimen["id"], observation["id"]


def _register_reviewers(service: ForensicService) -> None:
    for name in ("复核人乙", "复核人丙"):
        service.opinions.register_reviewer({
            "reviewer": name, "discipline": "法医物证", "note": "持证", "actor": "质量负责人",
        })


def _create_opinion(service: ForensicService, case_id: int, exam_id: int, specimen_id: int,
                    observation_id: int | None = None, *, opinion_no: str = "OP-1",
                    actor: str = "鉴定人甲", deadline_hours: int = 72,
                    body: str = "鉴定意见正文") -> dict:
    return service.opinions.create_opinion({
        "opinion_no": opinion_no, "case_id": case_id, "examination_id": exam_id, "title": "鉴定意见书",
        "body": body,
        "cited_specimen_ids": [specimen_id] if specimen_id != 999_999 else [999_999],
        "cited_observation_ids": [observation_id] if observation_id else [],
        "cited_protocol_id": None, "declaration_note": "所引检材、观察记录与方法版本均真实有效",
        "deadline_hours": deadline_hours, "actor": actor,
    })


def _approve_clean_round(service: ForensicService, opinion_id: int, reviewer: str, note: str = "通过") -> dict:
    detail = service.opinions.decide_review(opinion_id, {"approve": True, "note": note, "reviewer": reviewer})
    return detail


def test_version_is_immutable_and_declares_citations(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id)
        version = opinion["versions"][0]
        assert version["version_no"] == 1
        assert len(version["content_hash"]) == 64
        assert version["cited_specimen_ids"] == [specimen_id]
        assert version["cited_protocol_version"] == 1
        # 引用不属于本案件的检材必须被拒绝
        with pytest.raises(ValidationError):
            _create_opinion(service, case_id, exam_id, 999_999, observation_id, opinion_no="OP-BAD")


def test_claim_enforces_recusal_qualification_and_single_success(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id)

        with pytest.raises(ConflictError, match="不得为同一人"):
            service.opinions.claim(opinion["id"], "鉴定人甲")
        with pytest.raises(ConflictError, match="资质"):
            service.opinions.claim(opinion["id"], "未登记人员")

        claimed = service.opinions.claim(opinion["id"], "复核人乙")
        assert claimed["claimed_by"] == "复核人乙"
        # 并发领取只能成功一次
        with pytest.raises(ConflictError, match="已被其他复核人领取"):
            service.opinions.claim(opinion["id"], "复核人丙")


def test_finding_requires_location_severity_and_full_revision_cycle(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id)
        oid = opinion["id"]
        service.opinions.claim(oid, "复核人乙")

        finding = service.opinions.add_finding(oid, "复核人乙", {
            "location": "正文第3页数据表第2行", "severity": "blocking",
            "description": "位点计数与观察记录不一致",
        })
        assert finding["location"] and finding["severity"] == "blocking"
        detail = service.opinions.decide_review(oid, {
            "approve": False, "note": "退修", "reviewer": "复核人乙",
        })
        assert detail["status"] == "revision"

        # 必须先形成新版本，才能逐条回应问题
        with pytest.raises(ConflictError, match="新报告版本"):
            service.opinions.respond_finding(finding["id"], {"note": "已改", "accept": True, "actor": "鉴定人甲"})

        revised = service.opinions.add_revision(oid, {
            "body": "鉴定意见正文（数据已核对）", "cited_specimen_ids": [specimen_id],
            "cited_observation_ids": [observation_id], "cited_protocol_id": None,
            "declaration_note": "声明", "change_note": "更正数据表", "actor": "鉴定人甲",
        })
        # 旧版本正文不得随新版本被改写
        assert revised["versions"][0]["body"] == "鉴定意见正文"
        assert revised["versions"][1]["body"] == "鉴定意见正文（数据已核对）"

        service.opinions.respond_finding(finding["id"], {
            "note": "已按观察记录逐条更正", "accept": True, "actor": "鉴定人甲",
        })
        service.opinions.resubmit(oid, {"change_note": "修改完成", "deadline_hours": 72, "actor": "鉴定人甲"})
        service.opinions.claim(oid, "复核人丙")
        service.opinions.close_finding(finding["id"], "复核人丙", True, "复核确认")
        approved = _approve_clean_round(service, oid, "复核人丙")
        assert approved["status"] == "approved"
        assert approved["approved_version_id"] == approved["versions"][1]["id"]


def test_blocking_finding_blocks_issue_until_closed(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id)
        oid = opinion["id"]
        service.opinions.claim(oid, "复核人乙")
        service.opinions.add_finding(oid, "复核人乙", {
            "location": "结论段", "severity": "blocking", "description": "结论依据不足",
        })
        minor = service.opinions.add_finding(oid, "复核人乙", {
            "location": "落款", "severity": "minor", "description": "格式问题",
        })
        # 还有阻断意见未关闭时不能复核通过
        with pytest.raises(ConflictError, match="未确认关闭"):
            service.opinions.decide_review(oid, {"approve": True, "note": "通过", "reviewer": "复核人乙"})
        # 退修无问题不允许（必须至少提一条未关闭问题）——这里已有问题，正常退修
        service.opinions.decide_review(oid, {"approve": False, "note": "退修", "reviewer": "复核人乙"})
        service.opinions.add_revision(oid, {
            "body": "正文v2", "cited_specimen_ids": [specimen_id], "cited_observation_ids": [observation_id],
            "cited_protocol_id": None, "declaration_note": "声明", "change_note": "改", "actor": "鉴定人甲",
        })
        # 只处理 minor，阻断意见仍 open：不允许重新送审
        with pytest.raises(ConflictError, match="未逐条处理"):
            service.opinions.resubmit(oid, {"actor": "鉴定人甲"})


def test_issue_rejects_when_cited_examination_invalidated(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id)
        oid = opinion["id"]
        service.opinions.claim(oid, "复核人乙")
        approved = service.opinions.decide_review(oid, {"approve": True, "note": "通过", "reviewer": "复核人乙"})
        # 复核通过后、签发前，所引检验被作废
        service.examinations.invalidate_examination(exam_id, {
            "expected_version": 3, "reason": "发现原始记录异常", "actor": "质量负责人",
        })
        with pytest.raises(ConflictError, match="所引检验已不再有效"):
            service.opinions.issue(oid, {
                "actor": "质量负责人", "note": "签发", "expected_version": approved["version"],
            })


def test_overdue_reassignment_keeps_original_responsibility_chain(client):
    base = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
    clock = FrozenClock(base)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id, deadline_hours=1)
        oid = opinion["id"]
        service.opinions.claim(oid, "复核人乙")

        clock.advance(hours=2)
        detail = service.opinions.reassign_overdue(oid, {
            "reviewer": "复核人丙", "reason": "逾期未完成复核", "deadline_hours": 24, "actor": "质量负责人",
        })
        first, second = detail["assignments"]
        assert first["status"] == "expired_reassigned"
        assert first["claimed_by"] == "复核人乙"
        assert first["reassigned_by"] == "质量负责人"
        assert second["reviewer"] == "复核人丙"
        # 新任务仍须本人领取，且原领取人不能再操作
        claimed = service.opinions.claim(oid, "复核人丙")
        assert claimed["sequence_no"] == second["sequence_no"]
        with pytest.raises(ConflictError):
            service.opinions.add_finding(oid, "复核人乙", {
                "location": "x", "severity": "minor", "description": "无权操作",
            })

    with transaction(immediate=True) as connection:
        service = ForensicService(connection, FrozenClock(base))
        timeline = service.opinions.timeline(oid)
        types = [event["event_type"] for event in timeline["events"]]
        assert "claimed" in types and "review_reassigned" in types
        assert timeline["assignments"][0]["claimed_by"] == "复核人乙"


def test_reassign_before_deadline_rejected(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id, deadline_hours=72)
        with pytest.raises(ConflictError, match="尚未逾期"):
            service.opinions.reassign_overdue(opinion["id"], {
                "reviewer": None, "reason": "催促", "deadline_hours": 24, "actor": "质量负责人",
            })


def test_timeline_reconstructs_full_chain_and_issuance_proof(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        case_id, exam_id, specimen_id, observation_id = _build_completed_examination(service)
        _register_reviewers(service)
        opinion = _create_opinion(service, case_id, exam_id, specimen_id, observation_id)
        oid = opinion["id"]
        service.opinions.claim(oid, "复核人乙")
        finding = service.opinions.add_finding(oid, "复核人乙", {
            "location": "第2页", "severity": "blocking", "description": "问题",
        })
        service.opinions.decide_review(oid, {"approve": False, "note": "退修", "reviewer": "复核人乙"})
        service.opinions.add_revision(oid, {
            "body": "正文v2", "cited_specimen_ids": [specimen_id], "cited_observation_ids": [observation_id],
            "cited_protocol_id": None, "declaration_note": "声明", "change_note": "修改", "actor": "鉴定人甲",
        })
        service.opinions.respond_finding(finding["id"], {"note": "已修改", "accept": True, "actor": "鉴定人甲"})
        service.opinions.resubmit(oid, {"change_note": "完成", "deadline_hours": 72, "actor": "鉴定人甲"})
        service.opinions.claim(oid, "复核人丙")
        service.opinions.close_finding(finding["id"], "复核人丙", True, "确认")
        approved = service.opinions.decide_review(oid, {"approve": True, "note": "通过", "reviewer": "复核人丙"})
        issued = service.opinions.issue(oid, {
            "actor": "质量负责人", "note": "准予签发", "expected_version": approved["version"],
        })
        assert issued["status"] == "issued"

        timeline = service.opinions.timeline(oid)
        event_types = {event["event_type"] for event in timeline["events"]}
        assert {"created", "version_submitted", "review_pooled", "claimed", "finding_raised",
                "review_returned", "finding_responded", "review_approved", "issued"} <= event_types
        # 问题处理过程（提出/回应/关闭）完整可查
        finding_event_types = [event["event_type"] for event in timeline["finding_events"]]
        assert finding_event_types == ["finding_raised", "finding_responded", "finding_closed"]
        # 统一时间线按因果顺序记录主流程事件与问题事件
        unified_types = [event["event_type"] for event in timeline["timeline"]]
        assert unified_types.index("finding_raised") < unified_types.index("review_returned")
        # 回应问题发生在第二轮重新送审（最后一次入池）之前
        assert unified_types.index("finding_responded") < len(unified_types) - unified_types[::-1].index("review_pooled") - 1
        assert unified_types.index("finding_closed") < unified_types.index("review_approved")
        assert unified_types.index("review_approved") < unified_types.index("issued")
        proof = timeline["issuance_proof"]
        assert proof["version_match"] is True
        assert proof["hash_match"] is True
        assert proof["recomputed_hash_match"] is True
        assert proof["issued_version_no"] == 2
