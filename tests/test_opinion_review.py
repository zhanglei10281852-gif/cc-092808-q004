from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.clock import FrozenClock
from app.core.errors import ConflictError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.database import transaction
from app.forensics.service import ForensicService
from app.services.auth import AuthService
from app.services.identity import IdentityService

from tests.test_forensics_workflow import create_stored_lot


SECTIONS_V1 = {
    "基本情况": "委托人张某与检材的基本情况记载。",
    "检验过程": "采用规程方法对检材逐项检验，记录完整。",
    "分析说明": "检见特征与比对样本存在符合与差异点。",
    "鉴定意见": "倾向认定同一，需结合其他证据综合判断。",
}


def _bootstrap_users(service: ForensicService) -> dict[str, dict]:
    auth = AuthService(service.connection, service.opinions.clock)
    admin_row = auth.bootstrap_admin("admin", "Admin!23456", "管理员")
    admin = Principal(
        user_id=admin_row["id"], username="admin", display_name="管理员",
        department_id=None, permissions=frozenset({"*"}), session_id=1,
    )
    identity = IdentityService(service.connection, service.opinions.clock)

    def make(username: str, display: str, role: str) -> dict:
        return identity.create_user(admin, {
            "username": username, "password": "Passw0rd!23", "display_name": display,
            "role_codes": [role],
        })

    expert = make("expert01", "鉴定人甲", "technician")
    reviewer_a = make("review01", "复核人甲", "curator")
    reviewer_b = make("review02", "复核人乙", "curator")
    quality = make("quality01", "质量负责人", "quality_manager")
    return {"admin": admin, "expert": expert, "reviewer_a": reviewer_a,
            "reviewer_b": reviewer_b, "quality": quality}


def _actor(user: dict) -> dict:
    return {"id": user["id"], "display_name": user["display_name"]}


def build_completed_examination(service: ForensicService) -> dict:
    _forensic_case, specimen, _placement = create_stored_lot(service, "100")
    protocol = service.examinations.create_protocol({
        "protocol_code": "DNA-REVIEW", "discipline": "法医物证", "observation_target": 100,
        "checkpoint_count": 2, "reference_value": 0.99, "turnaround_days": 14,
        "conclusion_rule": "位点质量满足复核阈值", "created_by": "技术负责人",
    })
    test = service.examinations.schedule_examination({
        "examination_no": "EX-100", "specimen_id": specimen["id"], "protocol_id": protocol["id"],
        "examination_type": "补充检验", "sample_quantity": 5, "scheduled_for": "2026-09-25",
        "requested_by": "检验员", "idempotency_key": "schedule-op-100",
    })
    service.examinations.start_examination(test["id"], {"performed_by": "检验员", "expected_version": 1})
    observation_ids = []
    for checkpoint, normal in [(1, 90), (2, 92)]:
        observation = service.examinations.add_observation(test["id"], {
            "checkpoint_no": checkpoint, "items_checked": 100, "conforming_count": normal,
            "exception_count": 4, "unusable_count": 100 - normal - 4, "pending_count": 0,
            "sequence_no": 14, "observed_by": "检验员",
        })
        observation_ids.append(observation["id"])
    completed = service.examinations.complete_examination(
        test["id"], {"performed_by": "检验员", "expected_version": 2}
    )
    return {"specimen": specimen, "protocol": protocol, "examination": completed,
            "observation_ids": observation_ids}


def _references(bundle: dict) -> list[dict]:
    return [
        {"ref_type": "specimen", "ref_id": bundle["specimen"]["id"], "ref_label": "血痕检材"},
        {"ref_type": "observation", "ref_id": bundle["observation_ids"][0], "ref_label": "位点检查点1"},
        {"ref_type": "observation", "ref_id": bundle["observation_ids"][1], "ref_label": "位点检查点2"},
        {"ref_type": "protocol", "ref_id": bundle["protocol"]["id"], "ref_label": "DNA 检验规程"},
    ]


def _create_submitted_opinion(service: ForensicService, users: dict, sections: dict | None = None) -> dict:
    bundle = build_completed_examination(service)
    opinion = service.opinions.create_opinion({
        "opinion_no": "OP-100", "case_id": bundle["specimen"]["forensic_case"]["id"],
        "examination_id": bundle["examination"]["id"], "title": "亲缘关系鉴定意见",
    }, _actor(users["expert"]))
    submitted = service.opinions.submit_version(opinion["id"], {
        "sections": sections or SECTIONS_V1, "references": _references(bundle),
        "change_summary": "首次提交", "responses": [],
    }, _actor(users["expert"]))
    return {"bundle": bundle, "opinion": submitted}


def test_full_review_issue_and_timeline_proof(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        result = _create_submitted_opinion(service, users)
        opinion = result["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])

        claimed = service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        assert claimed["status"] == "claimed"

        decision = service.opinions.decide_review(task["id"], {
            "approve": True, "summary": "依据充分，同意通过", "confirmed_sections": ["鉴定意见", "检验过程"],
            "resolutions": [],
        }, _actor(users["reviewer_a"]))
        assert decision["result"] == "approved"

        passed = service.repository.require_opinion(opinion["id"])
        assert passed["status"] == "review_passed"

        issued = service.opinions.issue_opinion(opinion["id"], _actor(users["quality"]))
        assert issued["status"] == "issued"

        timeline = service.opinions.timeline(opinion["id"])
        event_types = [event["type"] for event in timeline["events"]]
        assert "version" in event_types and "claim" in event_types
        assert "review" in event_types and "issued" in event_types

        proof = timeline["issuance_proof"]
        assert proof["approved_version_matches_issued"] is True
        assert proof["issued_version_no"] == 1
        approved_version = service.repository.require_version(issued["issued_version_id"])
        assert proof["content_hash"] == approved_version["content_hash"]
        assert proof["approval"]["reviewer_name"] == "复核人甲"
        assert {ref["current_status"] for ref in proof["references"]} == {"valid"}
        assert issued["issue_evidence"]["issued_version_id"] == issued["issued_version_id"]


def test_expert_cannot_review_own_opinion(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        opinion = _create_submitted_opinion(service, users)["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        with pytest.raises(PermissionDeniedError):
            service.opinions.claim_task(task["id"], _actor(users["expert"]))


def test_conflict_of_interest_blocks_claim(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        opinion = _create_submitted_opinion(service, users)["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.add_conflict(opinion["id"], {
            "user_id": users["reviewer_a"]["id"], "reason": "曾参与检材提取",
        }, _actor(users["quality"]))
        with pytest.raises(PermissionDeniedError):
            service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        # 无回避情形的另一复核人可以正常领取
        claimed = service.opinions.claim_task(task["id"], _actor(users["reviewer_b"]))
        assert claimed["reviewer_name"] == "复核人乙"


def test_concurrent_claim_succeeds_only_once(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        opinion = _create_submitted_opinion(service, users)["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        with pytest.raises(ConflictError):
            service.opinions.claim_task(task["id"], _actor(users["reviewer_b"]))


def test_finding_must_point_to_real_section(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        opinion = _create_submitted_opinion(service, users)["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        with pytest.raises(ValidationError):
            service.opinions.add_finding(task["id"], {
                "location_ref": "不存在的章节", "severity": "major",
                "handling": "must_revise", "description": "定位无效",
            }, _actor(users["reviewer_a"]))


def test_return_revision_close_blocking_then_issue(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        result = _create_submitted_opinion(service, users)
        opinion = result["opinion"]
        first_task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(first_task["id"], _actor(users["reviewer_a"]))
        finding = service.opinions.add_finding(first_task["id"], {
            "location_ref": "鉴定意见", "severity": "critical", "handling": "must_revise",
            "description": "结论表述超出检验结果支持范围",
        }, _actor(users["reviewer_a"]))
        assert finding["blocking"] == 1
        service.opinions.decide_review(first_task["id"], {
            "approve": False, "summary": "结论需收敛", "confirmed_sections": ["基本情况"],
            "resolutions": [],
        }, _actor(users["reviewer_a"]))
        assert service.repository.require_opinion(opinion["id"])["status"] == "returned"

        # 退修新版本必须逐条回应，且改正被指出的章节
        sections_v2 = dict(SECTIONS_V1)
        sections_v2["鉴定意见"] = "依据现有检验结果，出具限定条件下的同一性意见。"
        with pytest.raises(ConflictError):
            service.opinions.submit_version(opinion["id"], {
                "sections": sections_v2, "references": _references(result["bundle"]),
                "change_summary": "收敛结论", "responses": [],
            }, _actor(users["expert"]))

        service.opinions.submit_version(opinion["id"], {
            "sections": sections_v2, "references": _references(result["bundle"]),
            "change_summary": "按阻断意见收敛结论表述",
            "responses": [{"finding_id": finding["id"], "response_text": "已删除超出检验支持的表述"}],
        }, _actor(users["expert"]))
        second_task = service.repository.opinion_active_task(opinion["id"])
        assert second_task["round_no"] == first_task["round_no"] + 1
        service.opinions.claim_task(second_task["id"], _actor(users["reviewer_b"]))

        # 鉴定人不能关闭问题，只有领取任务的复核人可以
        with pytest.raises(ConflictError):
            service.opinions.resolve_finding(finding["id"], "resolved", "已核实修改", _actor(users["expert"]))
        service.opinions.resolve_finding(
            finding["id"], "resolved", "新版本已按要求修改", _actor(users["reviewer_b"])
        )
        service.opinions.decide_review(second_task["id"], {
            "approve": True, "summary": "阻断意见已关闭", "confirmed_sections": [], "resolutions": [],
        }, _actor(users["reviewer_b"]))
        issued = service.opinions.issue_opinion(opinion["id"], _actor(users["quality"]))
        assert issued["status"] == "issued"
        assert issued["issued_version_id"] != result["opinion"]["approved_version_id"]

        timeline = service.opinions.timeline(opinion["id"])
        types = [event["type"] for event in timeline["events"]]
        assert types.count("version") == 2
        assert "revision_response" in types
        assert timeline["issuance_proof"]["issued_version_no"] == 2


def test_confirmed_section_cannot_be_rewritten(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        result = _create_submitted_opinion(service, users)
        opinion = result["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        service.opinions.add_finding(task["id"], {
            "location_ref": "鉴定意见", "severity": "minor", "handling": "explain",
            "description": "建议补充置信度说明",
        }, _actor(users["reviewer_a"]))
        service.opinions.decide_review(task["id"], {
            "approve": False, "summary": "补充说明", "confirmed_sections": ["基本情况", "检验过程"],
            "resolutions": [],
        }, _actor(users["reviewer_a"]))
        open_finding = service.repository.opinion_findings(opinion["id"])[0]

        sections_v2 = dict(SECTIONS_V1)
        sections_v2["基本情况"] = "基本情况被违规改写。"
        with pytest.raises(ConflictError, match="已复核通过"):
            service.opinions.submit_version(opinion["id"], {
                "sections": sections_v2, "references": _references(result["bundle"]),
                "change_summary": "",
                "responses": [{"finding_id": open_finding["id"], "response_text": "已在分析说明中补充置信度"}],
            }, _actor(users["expert"]))

        # 仅修改未确认章节、保留已确认章节逐字不变，则允许提交新版本
        sections_v2 = dict(SECTIONS_V1)
        sections_v2["分析说明"] = SECTIONS_V1["分析说明"] + " 综合置信度约 92%。"
        submitted_v2 = service.opinions.submit_version(opinion["id"], {
            "sections": sections_v2, "references": _references(result["bundle"]),
            "change_summary": "补充置信度说明",
            "responses": [{"finding_id": open_finding["id"], "response_text": "已在分析说明中补充置信度"}],
        }, _actor(users["expert"]))
        assert submitted_v2["current_version_no"] == 2


def test_cannot_submit_identical_version_without_revision(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        result = _create_submitted_opinion(service, users)
        opinion = result["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        service.opinions.decide_review(task["id"], {
            "approve": True, "summary": "直接通过", "confirmed_sections": [], "resolutions": [],
        }, _actor(users["reviewer_a"]))
        # 复核通过后状态锁定，鉴定人不能再覆盖提交新版本
        with pytest.raises(ConflictError):
            service.opinions.submit_version(opinion["id"], {
                "sections": SECTIONS_V1, "references": _references(result["bundle"]),
                "change_summary": "", "responses": [],
            }, _actor(users["expert"]))


def test_issue_blocked_when_referenced_examination_invalidated(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        result = _create_submitted_opinion(service, users)
        opinion = result["opinion"]
        examination_id = result["bundle"]["examination"]["id"]
        task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        service.opinions.decide_review(task["id"], {
            "approve": True, "summary": "通过", "confirmed_sections": [], "resolutions": [],
        }, _actor(users["reviewer_a"]))
        service.examinations.invalidate_examination(examination_id, {
            "expected_version": 3, "reason": "发现污染，检验结果作废", "actor": "质量负责人",
        })
        with pytest.raises(ConflictError):
            service.opinions.issue_opinion(opinion["id"], _actor(users["quality"]))


def test_overdue_pending_task_reassigned_with_chain_preserved(client):
    clock = FrozenClock(datetime(2026, 10, 1, 9, 0, tzinfo=UTC))
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        users = _bootstrap_users(service)
        opinion = _create_submitted_opinion(service, users)["opinion"]
        first_task = service.repository.opinion_active_task(opinion["id"])

        # 未逾期不允许重新分派
        with pytest.raises(ConflictError):
            service.opinions.reassign_task(first_task["id"], {
                "reviewer_id": None, "claim_due_hours": 48, "review_due_hours": 168,
                "reason": "提前干预",
            }, _actor(users["quality"]))

        clock.advance(hours=49)
        assert len(service.opinions.overdue_tasks()) == 1
        new_task = service.opinions.reassign_task(first_task["id"], {
            "reviewer_id": users["reviewer_b"]["id"], "claim_due_hours": 48,
            "review_due_hours": 168, "reason": "逾期未领取，重新分派",
        }, _actor(users["quality"]))

        assert service.repository.require_task(first_task["id"])["status"] == "reassigned"
        assert new_task["reassigned_from_task_id"] == first_task["id"]
        # 指定给复核人乙后，复核人甲不能领取
        with pytest.raises(PermissionDeniedError):
            service.opinions.claim_task(new_task["id"], _actor(users["reviewer_a"]))
        service.opinions.claim_task(new_task["id"], _actor(users["reviewer_b"]))

        timeline = service.opinions.timeline(opinion["id"])
        reassign_events = [e for e in timeline["events"] if e["type"] == "reassign"]
        assert len(reassign_events) == 1
        # 原任务记录仍在，责任链可追溯
        all_tasks = service.opinions.detail(opinion["id"])["tasks"]
        assert [task["status"] for task in all_tasks] == ["reassigned", "claimed"]


def test_overdue_claimed_task_reassigned_keeps_previous_reviewer(client):
    clock = FrozenClock(datetime(2026, 10, 1, 9, 0, tzinfo=UTC))
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        users = _bootstrap_users(service)
        opinion = _create_submitted_opinion(service, users)["opinion"]
        first_task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(first_task["id"], _actor(users["reviewer_a"]))
        clock.advance(hours=200)  # 超过复核期限 168 小时
        new_task = service.opinions.reassign_task(first_task["id"], {
            "reviewer_id": None, "claim_due_hours": 48, "review_due_hours": 168,
            "reason": "领取后逾期未出具结论",
        }, _actor(users["quality"]))
        old = service.repository.require_task(first_task["id"])
        assert old["status"] == "reassigned" and old["reviewer_name"] == "复核人甲"
        assert new_task["reviewer_id"] is None
        # 新任务进入可领取池，复核人乙可领取
        pool = service.opinions.pending_task_pool(_actor(users["reviewer_b"]))
        assert any(task["id"] == new_task["id"] for task in pool)


def test_blocking_finding_reopens_only_its_confirmed_section(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        result = _create_submitted_opinion(service, users)
        opinion = result["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        service.opinions.claim_task(task["id"], _actor(users["reviewer_a"]))
        # 阻断问题落在「基本情况」，同时复核人确认了「基本情况」和「检验过程」
        finding = service.opinions.add_finding(task["id"], {
            "location_ref": "基本情况", "severity": "major", "handling": "must_revise",
            "description": "委托时间记载错误，需更正",
        }, _actor(users["reviewer_a"]))
        service.opinions.decide_review(task["id"], {
            "approve": False, "summary": "更正基本情况",
            "confirmed_sections": ["基本情况", "检验过程"], "resolutions": [],
        }, _actor(users["reviewer_a"]))

        # 有开放阻断问题的「基本情况」可返工，但无问题的「检验过程」仍冻结
        sections_v2 = dict(SECTIONS_V1)
        sections_v2["基本情况"] = "更正后的委托与检材基本情况记载。"
        sections_v2["检验过程"] = "试图改写已确认的检验过程章节。"
        with pytest.raises(ConflictError, match="已复核通过"):
            service.opinions.submit_version(opinion["id"], {
                "sections": sections_v2, "references": _references(result["bundle"]),
                "change_summary": "",
                "responses": [{"finding_id": finding["id"], "response_text": "已更正委托时间"}],
            }, _actor(users["expert"]))

        # 只返工被阻断的章节，提交成功
        sections_v2 = dict(SECTIONS_V1)
        sections_v2["基本情况"] = "更正后的委托与检材基本情况记载。"
        submitted = service.opinions.submit_version(opinion["id"], {
            "sections": sections_v2, "references": _references(result["bundle"]),
            "change_summary": "更正基本情况",
            "responses": [{"finding_id": finding["id"], "response_text": "已更正委托时间"}],
        }, _actor(users["expert"]))
        assert submitted["current_version_no"] == 2


def test_submission_requires_all_three_reference_types(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        bundle = build_completed_examination(service)
        opinion = service.opinions.create_opinion({
            "opinion_no": "OP-200", "case_id": bundle["specimen"]["forensic_case"]["id"],
            "examination_id": bundle["examination"]["id"], "title": "引用不全的意见",
        }, _actor(users["expert"]))
        with pytest.raises(ValidationError, match="检材、观察记录和方法版本"):
            service.opinions.submit_version(opinion["id"], {
                "sections": SECTIONS_V1,
                "references": [
                    {"ref_type": "specimen", "ref_id": bundle["specimen"]["id"], "ref_label": "仅检材"},
                ],
                "change_summary": "首次提交", "responses": [],
            }, _actor(users["expert"]))


def test_only_quality_manager_can_reassign(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        users = _bootstrap_users(service)
        opinion = _create_submitted_opinion(service, users)["opinion"]
        task = service.repository.opinion_active_task(opinion["id"])
        with pytest.raises(PermissionDeniedError):
            service.opinions.reassign_task(task["id"], {
                "reviewer_id": None, "claim_due_hours": 48, "review_due_hours": 168, "reason": "越权",
            }, _actor(users["reviewer_a"]))
