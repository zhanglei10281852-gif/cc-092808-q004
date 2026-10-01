from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.forensics.repository import ForensicRepository, record, records

BLOCKING_SEVERITIES = {"major", "critical"}
CLAIM_DUE_HOURS = 48
REVIEW_DUE_HOURS = 168


def _canonical(sections: dict[str, str]) -> str:
    return json.dumps(sections, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_hash_of(sections: dict[str, str]) -> str:
    return hashlib.sha256(_canonical(sections).encode("utf-8")).hexdigest()


class OpinionReviewService:
    """鉴定意见签发前复核：不可覆盖版本、回避领取、退修闭环与签发留证。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    # ------------------------------------------------------------------ 创建

    def create_opinion(self, data: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        forensic_case = self.repository.require_forensic_case(int(data["case_id"]))
        examination = self.repository.require_examination(int(data["examination_id"]))
        if int(examination["specimen_id"]) and self.repository.require_specimen(int(examination["specimen_id"]))["case_id"] != forensic_case["id"]:
            raise ValidationError("检验任务不属于该鉴定案件")
        if examination["status"] != "completed":
            raise ConflictError("只有已完成的检验可以据此撰写鉴定意见")
        if self.repository.opinion_by_number(data["opinion_no"]):
            raise ConflictError("鉴定意见编号已经存在")
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO expert_opinions(opinion_no,case_id,examination_id,discipline,title,status,expert_id,"
                "expert_name,current_version_no,version,created_at,updated_at) VALUES(?,?,?,?,?, 'draft',?,?,0,1,?,?)",
                (
                    data["opinion_no"], forensic_case["id"], examination["id"], forensic_case["discipline"],
                    data.get("title", ""), actor["id"], actor["display_name"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("鉴定意见编号已经存在") from exc
        opinion_id = int(cursor.lastrowid)
        self._event(opinion_id, "created", actor, {"opinion_no": data["opinion_no"], "examination_id": examination["id"]})
        return self.detail(opinion_id)

    # ------------------------------------------------------ 提交不可覆盖版本

    def submit_version(self, opinion_id: int, data: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        opinion = self.repository.require_opinion(opinion_id)
        if opinion["status"] not in {"draft", "returned"}:
            raise ConflictError("只有草稿或退修中的鉴定意见可以提交版本", context={"status": opinion["status"]})
        if int(opinion["expert_id"]) != int(actor["id"]):
            raise PermissionDeniedError("只有鉴定人本人可以提交报告版本")

        references = self._validate_references(
            data["references"], int(opinion["case_id"]), opinion["discipline"]
        )
        sections = data["sections"]
        digest = content_hash_of(sections)
        previous = self.repository.latest_version(opinion_id)
        open_findings = [f for f in self.repository.opinion_findings(opinion_id) if f["status"] == "open"]
        if previous and previous["content_hash"] == digest and not open_findings and not data.get("change_summary", "").strip():
            raise ConflictError("新版本正文与上一版完全相同，且没有退修意见需要处理或变更说明")

        responses = {int(item["finding_id"]): item["response_text"] for item in data.get("responses", [])}
        if open_findings:
            missing = [f["id"] for f in open_findings if f["id"] not in responses]
            if missing:
                raise ConflictError("退修意见必须逐条回应后才能重新提交", context={"missing_finding_ids": missing})

        self._assert_confirmed_sections_unchanged(previous, sections)

        timestamp = to_storage(self.clock.now())
        new_version_no = int(opinion["current_version_no"]) + 1
        cursor = self.connection.execute(
            "INSERT INTO opinion_versions(opinion_id,version_no,parent_version_id,report_sections_json,content_hash,"
            "change_summary,submitted_by,submitted_by_name,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                opinion_id, new_version_no,
                previous["id"] if previous else None,
                json.dumps(sections, ensure_ascii=False, sort_keys=True), digest,
                data.get("change_summary", ""), actor["id"], actor["display_name"], timestamp,
            ),
        )
        version_id = int(cursor.lastrowid)
        for ref in references:
            self.connection.execute(
                "INSERT INTO opinion_version_references(version_id,ref_type,ref_id,ref_label,snapshot_json) VALUES(?,?,?,?,?)",
                (version_id, ref["ref_type"], ref["ref_id"], ref.get("ref_label", ""),
                 json.dumps(ref["snapshot"], ensure_ascii=False, sort_keys=True, default=str)),
            )
        for finding in open_findings:
            self.connection.execute(
                "INSERT INTO finding_responses(finding_id,version_id,response_text,responded_by,responded_by_name,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (finding["id"], version_id, responses[finding["id"]], actor["id"], actor["display_name"], timestamp),
            )
            self.connection.execute(
                "UPDATE review_findings SET addressed_in_version_id=?,updated_at=? WHERE id=?",
                (version_id, timestamp, finding["id"]),
            )

        self.connection.execute(
            "UPDATE expert_opinions SET status='pending_review',current_version_no=?,approved_version_id=NULL,"
            "version=version+1,updated_at=? WHERE id=?",
            (new_version_no, timestamp, opinion_id),
        )
        max_round = self.connection.execute(
            "SELECT COALESCE(MAX(round_no),0) FROM review_tasks WHERE opinion_id=?", (opinion_id,)
        ).fetchone()[0]
        claim_due = self.clock.now() + timedelta(hours=CLAIM_DUE_HOURS)
        review_due = self.clock.now() + timedelta(hours=REVIEW_DUE_HOURS)
        task_cursor = self.connection.execute(
            "INSERT INTO review_tasks(opinion_id,version_id,round_no,status,claim_due_at,review_due_at,"
            "assigned_by,assigned_by_name,created_at,updated_at) VALUES(?,?,?, 'pending',?,?,NULL,NULL,?,?)",
            (
                opinion_id, version_id, int(max_round) + 1,
                claim_due.isoformat(timespec="seconds"), review_due.isoformat(timespec="seconds"),
                timestamp, timestamp,
            ),
        )
        task_id = int(task_cursor.lastrowid)
        self._event(opinion_id, "version_submitted", actor, {
            "version_id": version_id, "version_no": new_version_no,
            "content_hash": digest, "references": len(references), "task_id": task_id,
        })
        return self.detail(opinion_id)

    def _validate_references(self, refs: list[dict[str, Any]], case_id: int, discipline: str) -> list[dict[str, Any]]:
        seen: set[tuple[str, int]] = set()
        present_types: set[str] = set()
        normalized: list[dict[str, Any]] = []
        for raw in refs:
            key = (raw["ref_type"], int(raw["ref_id"]))
            if key in seen:
                raise ValidationError("引用的检材、观察记录或方法版本不能重复")
            seen.add(key)
            present_types.add(key[0])
            ref_type, ref_id = key
            snapshot: dict[str, Any]
            if ref_type == "specimen":
                specimen = self.repository.require_specimen(ref_id)
                if int(specimen["case_id"]) != case_id:
                    raise ValidationError("只能引用本鉴定案件下的检材")
                if specimen["status"] in {"depleted", "disposed"}:
                    raise ConflictError("引用的检材已经耗尽或销毁，不能作为鉴定依据")
                snapshot = {"specimen_no": specimen["specimen_no"], "status": specimen["status"],
                            "available_quantity": specimen["available_quantity"], "version": specimen["version"]}
            elif ref_type == "observation":
                row = self.connection.execute(
                    "SELECT o.*,e.status AS examination_status,e.specimen_id,s.case_id FROM examination_observations o "
                    "JOIN examinations e ON e.id=o.examination_id "
                    "JOIN specimens s ON s.id=e.specimen_id WHERE o.id=?", (ref_id,),
                ).fetchone()
                if row is None:
                    raise NotFoundError("引用的观察记录不存在")
                observation = record(row)
                if int(observation["case_id"]) != case_id:
                    raise ValidationError("只能引用本鉴定案件检验中的观察记录")
                if observation["examination_status"] != "completed":
                    raise ConflictError("引用的观察记录所属检验尚未完成或已作废")
                snapshot = {"examination_id": observation["examination_id"],
                            "checkpoint_no": observation["checkpoint_no"], "sequence_no": observation["sequence_no"],
                            "observed_by": observation["observed_by"]}
            else:
                protocol = self.repository.require_protocol(ref_id)
                if protocol["discipline"] != discipline:
                    raise ValidationError("引用的检验规程与鉴定意见的鉴定专业不匹配")
                if not int(protocol["active"]):
                    raise ConflictError("引用的检验规程版本已停用")
                snapshot = {"protocol_code": protocol["protocol_code"], "version": protocol["version"],
                            "discipline": protocol["discipline"]}
            normalized.append({"ref_type": ref_type, "ref_id": ref_id,
                               "ref_label": raw.get("ref_label", ""), "snapshot": snapshot})
        missing = {"specimen", "observation", "protocol"} - present_types
        if missing:
            labels = {"specimen": "检材", "observation": "观察记录", "protocol": "方法（检验规程）版本"}
            raise ValidationError("提交版本时必须同时声明所引用的检材、观察记录和方法版本",
                                  context={"missing": [labels[name] for name in sorted(missing)]})
        return normalized

    def _assert_confirmed_sections_unchanged(self, previous: dict[str, Any] | None, sections: dict[str, str]) -> None:
        """历轮已复核（确认）章节必须逐字保留，不能随本次正文一起被改写。

        例外：若某已确认章节上仍悬着开放的阻断性问题，则该章节必须允许返工，不做冻结，
        以免出现「既要求修改又禁止修改」的死锁。
        """
        if previous is None:
            return
        reopen_blocking = {
            f["location_ref"] for f in self.repository.opinion_findings(previous["opinion_id"])
            if f["blocking"] and f["status"] == "open"
        }
        tasks = records(self.connection.execute(
            "SELECT t.version_id,t.confirmed_sections_json FROM review_tasks t "
            "JOIN opinion_versions v ON v.id=t.version_id "
            "WHERE t.opinion_id=? AND t.confirmed_sections_json<>'[]' AND t.status IN ('approved','returned')",
            (previous["opinion_id"],),
        ).fetchall())
        for task in tasks:
            confirmed = task["confirmed_sections"]
            if not confirmed:
                continue
            base = self.repository.require_version(int(task["version_id"]))["sections"]
            for name in confirmed:
                if name in reopen_blocking:
                    continue
                if name not in sections:
                    raise ConflictError("已复核通过的章节不得在新版本中删除", context={"section": name})
                if sections[name] != base.get(name):
                    raise ConflictError("已复核通过的章节正文不得随本次退修改写", context={"section": name})

    # -------------------------------------------------------------- 回避名单

    def add_conflict(self, opinion_id: int, data: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        self.repository.require_opinion(opinion_id)
        user = self.repository.require_user(int(data["user_id"]))
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "INSERT INTO opinion_conflicts(opinion_id,user_id,reason,added_by,added_by_name,created_at) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(opinion_id,user_id) DO UPDATE SET reason=excluded.reason,added_by=excluded.added_by,"
            "added_by_name=excluded.added_by_name,created_at=excluded.created_at",
            (opinion_id, user["id"], data.get("reason", ""), actor["id"], actor["display_name"], timestamp),
        )
        self._event(opinion_id, "conflict_added", actor, {"user_id": user["id"], "reason": data.get("reason", "")})
        return {"opinion_id": opinion_id, "conflicts": self.repository.opinion_conflicts(opinion_id)}

    def _assert_eligible_reviewer(self, opinion: dict[str, Any], user: dict[str, Any]) -> None:
        user_id = int(user["id"])
        if "opinion.review" not in self.repository.user_permissions(user_id):
            raise PermissionDeniedError("该账号没有复核鉴定意见的权限")
        account = self.repository.require_user(user_id)
        if account["status"] != "active":
            raise PermissionDeniedError("复核人账号不可用")
        if user_id == int(opinion["expert_id"]):
            raise PermissionDeniedError("鉴定人与复核人不得是同一人")
        if self.connection.execute(
            "SELECT 1 FROM opinion_conflicts WHERE opinion_id=? AND user_id=?", (opinion["id"], user_id),
        ).fetchone():
            raise PermissionDeniedError("该复核人与本鉴定意见存在回避情形")

    # ------------------------------------------------------------ 领取复核任务

    def claim_task(self, task_id: int, actor: dict[str, Any]) -> dict[str, Any]:
        task = self.repository.require_task(task_id)
        opinion = self.repository.require_opinion(int(task["opinion_id"]))
        self._assert_eligible_reviewer(opinion, actor)
        if task["status"] != "pending":
            raise ConflictError("该复核任务已被领取或已结束", context={"status": task["status"]})
        if task["reviewer_id"] is not None and int(task["reviewer_id"]) != int(actor["id"]):
            raise PermissionDeniedError("该复核任务已指定其他复核人")
        timestamp = to_storage(self.clock.now())
        review_due = task["review_due_at"] or to_storage(self.clock.now() + timedelta(hours=REVIEW_DUE_HOURS))
        # 条件更新 + 部分唯一索引共同保证并发领取只能成功一次
        cursor = self.connection.execute(
            "UPDATE review_tasks SET status='claimed',reviewer_id=?,reviewer_name=?,claimed_at=?,review_due_at=?,"
            "updated_at=? WHERE id=? AND status='pending'",
            (actor["id"], actor["display_name"], timestamp, review_due, timestamp, task_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("该复核任务已被其他复核人领取")
        self.connection.execute(
            "UPDATE expert_opinions SET status='in_review',updated_at=? WHERE id=? AND status='pending_review'",
            (timestamp, opinion["id"]),
        )
        self._event(opinion["id"], "task_claimed", actor, {"task_id": task_id, "version_id": task["version_id"]})
        return self.task_detail(task_id)

    # ---------------------------------------------------------- 复核问题与结论

    def add_finding(self, task_id: int, data: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        task = self.repository.require_task(task_id)
        opinion = self.repository.require_opinion(int(task["opinion_id"]))
        self._assert_task_actor(task, opinion, actor)
        version = self.repository.require_version(int(task["version_id"]))
        sections = version["sections"]
        location = data["location_ref"].strip()
        if location not in sections:
            raise ValidationError("问题定位必须指向报告中的具体章节", context={"sections": list(sections)})
        blocking = 1 if data["severity"] in BLOCKING_SEVERITIES or data["handling"] == "must_revise" else 0
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO review_findings(opinion_id,task_id,version_id,round_no,location_ref,severity,handling,blocking,"
            "description,status,raised_by,raised_by_name,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?, 'open',?,?,?,?)",
            (
                opinion["id"], task_id, version["id"], int(task["round_no"]), location, data["severity"],
                data["handling"], blocking, data["description"].strip(), actor["id"], actor["display_name"],
                timestamp, timestamp,
            ),
        )
        self._event(opinion["id"], "finding_raised", actor, {
            "task_id": task_id, "finding_id": cursor.lastrowid, "location_ref": location,
            "severity": data["severity"], "blocking": bool(blocking),
        })
        return self.repository.require_finding(int(cursor.lastrowid))

    def _assert_task_actor(self, task: dict[str, Any], opinion: dict[str, Any], actor: dict[str, Any]) -> None:
        self._assert_eligible_reviewer(opinion, actor)
        if task["status"] != "claimed" or task["reviewer_id"] is None or int(task["reviewer_id"]) != int(actor["id"]):
            raise ConflictError("只有领取该任务的复核人可以操作")

    def decide_review(self, task_id: int, data: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        task = self.repository.require_task(task_id)
        opinion = self.repository.require_opinion(int(task["opinion_id"]))
        self._assert_task_actor(task, opinion, actor)
        timestamp = to_storage(self.clock.now())

        for item in data.get("resolutions", []):
            self._resolve_finding(int(item["finding_id"]), item["status"], item["note"], actor, opinion, timestamp)

        findings = self.repository.task_findings(task_id)
        open_blocking = [
            f for f in self.repository.opinion_findings(opinion["id"])
            if f["blocking"] and f["status"] == "open"
        ]
        if data["approve"] and open_blocking:
            raise ConflictError("仍有阻断性问题未关闭，不能复核通过",
                                context={"open_blocking": [f["id"] for f in open_blocking]})

        confirmed_sections = sorted(set(data.get("confirmed_sections", [])))
        version = self.repository.require_version(int(task["version_id"]))
        unknown = [name for name in confirmed_sections if name not in version["sections"]]
        if unknown:
            raise ValidationError("确认章节不属于当前报告版本", context={"unknown": unknown})

        if data["approve"]:
            # 阻断项已在上面拦截；仍开放的非阻断问题（minor/explain/note）随复核通过一并确认关闭，
            # 保证每条问题都有终局处理结论，而不是悬空。
            for nonblocking in self.repository.opinion_findings(opinion["id"]):
                if nonblocking["status"] == "open":
                    self.connection.execute(
                        "UPDATE review_findings SET status='resolved',resolution_note=?,"
                        "resolved_by=?,resolved_by_name=?,resolved_at=?,updated_at=? WHERE id=?",
                        (
                            "复核通过时确认：该非阻断问题已处理或无需返工",
                            actor["id"], actor["display_name"], timestamp, timestamp, nonblocking["id"],
                        ),
                    )
            self.connection.execute(
                "UPDATE review_tasks SET status='approved',completed_at=?,result='approved',summary=?,"
                "confirmed_sections_json=?,updated_at=? WHERE id=?",
                (timestamp, data.get("summary", ""),
                 json.dumps(confirmed_sections, ensure_ascii=False), timestamp, task_id),
            )
            self.connection.execute(
                "UPDATE expert_opinions SET status='review_passed',approved_version_id=?,updated_at=? WHERE id=?",
                (version["id"], timestamp, opinion["id"]),
            )
            self._event(opinion["id"], "review_approved", actor, {
                "task_id": task_id, "version_id": version["id"], "version_no": version["version_no"],
                "confirmed_sections": confirmed_sections,
            })
        else:
            if not findings:
                raise ConflictError("退修必须至少提出一条复核问题")
            self.connection.execute(
                "UPDATE review_tasks SET status='returned',completed_at=?,result='returned',summary=?,"
                "confirmed_sections_json=?,updated_at=? WHERE id=?",
                (timestamp, data.get("summary", ""),
                 json.dumps(confirmed_sections, ensure_ascii=False), timestamp, task_id),
            )
            self.connection.execute(
                "UPDATE expert_opinions SET status='returned',updated_at=? WHERE id=?", (timestamp, opinion["id"])
            )
            self._event(opinion["id"], "review_returned", actor, {
                "task_id": task_id, "version_id": version["id"],
                "blocking_findings": [f["id"] for f in findings if f["blocking"]],
                "confirmed_sections": confirmed_sections,
            })
        return self.task_detail(task_id)

    def resolve_finding(self, finding_id: int, status: str, note: str, actor: dict[str, Any]) -> dict[str, Any]:
        finding = self.repository.require_finding(finding_id)
        opinion = self.repository.require_opinion(int(finding["opinion_id"]))
        active_task = self.repository.opinion_active_task(opinion["id"])
        if active_task is None or active_task["status"] != "claimed" or active_task["reviewer_id"] is None \
                or int(active_task["reviewer_id"]) != int(actor["id"]):
            raise ConflictError("只有当前领取该意见复核任务的复核人可以关闭问题")
        timestamp = to_storage(self.clock.now())
        self._resolve_finding(finding_id, status, note, actor, opinion, timestamp)
        return self.repository.require_finding(finding_id)

    def _resolve_finding(self, finding_id: int, status: str, note: str, actor: dict[str, Any],
                         opinion: dict[str, Any], timestamp: str) -> None:
        finding = self.repository.require_finding(finding_id)
        if int(finding["opinion_id"]) != int(opinion["id"]):
            raise ValidationError("问题不属于当前鉴定意见")
        if finding["status"] != "open":
            raise ConflictError("该问题已经关闭", context={"status": finding["status"]})
        if status == "rejected" and not note.strip():
            raise ValidationError("驳回问题时必须填写理由")
        self.connection.execute(
            "UPDATE review_findings SET status=?,resolution_note=?,resolved_by=?,resolved_by_name=?,resolved_at=?,"
            "updated_at=? WHERE id=?",
            (status, note.strip(), actor["id"], actor["display_name"], timestamp, timestamp, finding_id),
        )
        self._event(int(finding["opinion_id"]), "finding_closed", actor,
                    {"finding_id": finding_id, "result": status})

    # ------------------------------------------------------------- 逾期重新分派

    def reassign_task(self, task_id: int, data: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        if "opinion.dispatch" not in self.repository.user_permissions(int(actor["id"])):
            raise PermissionDeniedError("只有质量负责人可以重新分派复核任务")
        task = self.repository.require_task(task_id)
        opinion = self.repository.require_opinion(int(task["opinion_id"]))
        if task["status"] not in {"pending", "claimed"}:
            raise ConflictError("只有进行中的复核任务可以重新分派", context={"status": task["status"]})
        now = self.clock.now()
        overdue = task["status"] == "pending" and task["claim_due_at"] and task["claim_due_at"] <= now.isoformat(timespec="seconds")
        claimed_expired = (
            task["status"] == "claimed" and task["review_due_at"]
            and task["review_due_at"] <= now.isoformat(timespec="seconds")
        )
        if not (overdue or claimed_expired):
            raise ConflictError("复核任务尚未逾期，不能重新分派")
        new_reviewer = None
        if data.get("reviewer_id") is not None:
            new_reviewer = self.repository.require_user(int(data["reviewer_id"]))
            self._assert_eligible_reviewer(opinion, new_reviewer)

        timestamp = to_storage(now)
        self.connection.execute(
            "UPDATE review_tasks SET status='reassigned',reassigned_at=?,updated_at=? WHERE id=?",
            (timestamp, timestamp, task_id),
        )
        claim_due = now + timedelta(hours=int(data["claim_due_hours"]))
        review_due = now + timedelta(hours=int(data["review_due_hours"]))
        cursor = self.connection.execute(
            "INSERT INTO review_tasks(opinion_id,version_id,round_no,status,reviewer_id,reviewer_name,assigned_by,"
            "assigned_by_name,reassigned_from_task_id,claim_due_at,review_due_at,created_at,updated_at) "
            "VALUES(?,?,?, 'pending',?,?,?,?,?,?,?,?,?)",
            (
                opinion["id"], task["version_id"], int(task["round_no"]) + 1,
                new_reviewer["id"] if new_reviewer else None,
                new_reviewer["display_name"] if new_reviewer else None,
                actor["id"], actor["display_name"], task_id,
                claim_due.isoformat(timespec="seconds"), review_due.isoformat(timespec="seconds"),
                timestamp, timestamp,
            ),
        )
        new_task_id = int(cursor.lastrowid)
        self.connection.execute(
            "UPDATE expert_opinions SET status='pending_review',updated_at=? WHERE id=? AND status='in_review'",
            (timestamp, opinion["id"]),
        )
        self._event(opinion["id"], "task_reassigned", actor, {
            "from_task_id": task_id, "new_task_id": new_task_id,
            "version_id": task["version_id"], "reason": data["reason"],
            "previous_reviewer_id": task["reviewer_id"],
        })
        return self.task_detail(new_task_id)

    # -------------------------------------------------------------------- 签发

    def issue_opinion(self, opinion_id: int, actor: dict[str, Any]) -> dict[str, Any]:
        if "opinion.issue" not in self.repository.user_permissions(int(actor["id"])):
            raise PermissionDeniedError("只有授权签发人（质量负责人）可以签发鉴定意见")
        opinion = self.repository.require_opinion(opinion_id)
        if opinion["status"] != "review_passed":
            raise ConflictError("只有复核通过的鉴定意见可以签发", context={"status": opinion["status"]})
        approved_version = self.repository.require_version(int(opinion["approved_version_id"]))

        open_blocking = self.connection.execute(
            "SELECT COUNT(*) FROM review_findings WHERE opinion_id=? AND blocking=1 AND status='open'", (opinion_id,)
        ).fetchone()[0]
        if int(open_blocking):
            raise ConflictError("仍有阻断意见未关闭，不能签发")

        examination = self.repository.require_examination(int(opinion["examination_id"]))
        if examination["status"] != "completed":
            raise ConflictError("鉴定意见所依据的检验已不再是有效完成状态，不能签发",
                                context={"examination_status": examination["status"]})

        evidence, still_valid = self._reference_evidence(approved_version)
        if not still_valid:
            raise ConflictError("最终版本引用的检材、观察记录或方法版本已失效，不能签发", context={"references": evidence})

        latest = self.repository.latest_version(opinion_id)
        if latest is None or int(latest["id"]) != int(approved_version["id"]):
            raise ConflictError("复核通过版本之后又产生了新版本，需要重新复核")

        timestamp = to_storage(self.clock.now())
        issue_evidence = {
            "issued_version_id": approved_version["id"],
            "issued_version_no": approved_version["version_no"],
            "content_hash": approved_version["content_hash"],
            "examination_id": examination["id"],
            "examination_status": examination["status"],
            "approved_task_id": self.connection.execute(
                "SELECT id FROM review_tasks WHERE opinion_id=? AND version_id=? AND status='approved' "
                "ORDER BY completed_at DESC,id DESC LIMIT 1", (opinion_id, approved_version["id"]),
            ).fetchone()[0],
            "references": evidence,
            "checked_at": timestamp,
        }
        self.connection.execute(
            "UPDATE expert_opinions SET status='issued',issued_version_id=?,issued_by=?,issued_by_name=?,issued_at=?,"
            "issue_evidence_json=?,version=version+1,updated_at=? WHERE id=?",
            (
                approved_version["id"], actor["id"], actor["display_name"], timestamp,
                json.dumps(issue_evidence, ensure_ascii=False, sort_keys=True, default=str), timestamp, opinion_id,
            ),
        )
        self._event(opinion_id, "issued", actor, {
            "version_id": approved_version["id"], "version_no": approved_version["version_no"],
            "content_hash": approved_version["content_hash"],
        })
        return self.detail(opinion_id)

    def _reference_evidence(self, version: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
        evidence: list[dict[str, Any]] = []
        valid = True
        for ref in self.repository.version_references(int(version["id"])):
            status = "valid"
            if ref["ref_type"] == "specimen":
                specimen = self.connection.execute(
                    "SELECT status,version FROM specimens WHERE id=?", (ref["ref_id"],),
                ).fetchone()
                if specimen is None or specimen[0] in {"depleted", "disposed"}:
                    status = "invalid"
            elif ref["ref_type"] == "observation":
                row = self.connection.execute(
                    "SELECT e.status FROM examination_observations o JOIN examinations e ON e.id=o.examination_id "
                    "WHERE o.id=?", (ref["ref_id"],),
                ).fetchone()
                if row is None or row[0] != "completed":
                    status = "invalid"
            else:
                protocol = self.connection.execute(
                    "SELECT active FROM examination_protocols WHERE id=?", (ref["ref_id"],),
                ).fetchone()
                if protocol is None or not int(protocol[0]):
                    status = "invalid"
            item = {"ref_type": ref["ref_type"], "ref_id": ref["ref_id"], "ref_label": ref["ref_label"],
                    "snapshot": ref["snapshot"], "current_status": status}
            evidence.append(item)
            if status != "valid":
                valid = False
        return evidence, valid

    # ----------------------------------------------------------------- 查询/时间线

    def pending_task_pool(self, actor: dict[str, Any]) -> list[dict[str, Any]]:
        """当前账号可以领取的待领取任务（已通过回避与权限筛选）。"""
        rows = records(self.connection.execute(
            "SELECT t.*,o.opinion_no,o.discipline,o.expert_name FROM review_tasks t "
            "JOIN expert_opinions o ON o.id=t.opinion_id WHERE t.status='pending' ORDER BY t.claim_due_at,t.id"
        ).fetchall())
        pool: list[dict[str, Any]] = []
        for task in rows:
            if task["reviewer_id"] is not None and int(task["reviewer_id"]) != int(actor["id"]):
                continue
            opinion = self.repository.require_opinion(int(task["opinion_id"]))
            try:
                self._assert_eligible_reviewer(opinion, actor)
            except PermissionDeniedError:
                continue
            pool.append(task)
        return pool

    def overdue_tasks(self) -> list[dict[str, Any]]:
        """逾期未领取或逾期未完成复核结论的任务，供质量负责人重新分派。"""
        now = to_storage(self.clock.now())
        return records(self.connection.execute(
            "SELECT t.*,o.opinion_no,o.discipline,o.expert_name FROM review_tasks t "
            "JOIN expert_opinions o ON o.id=t.opinion_id "
            "WHERE (t.status='pending' AND t.claim_due_at<?) "
            "OR (t.status='claimed' AND t.review_due_at IS NOT NULL AND t.review_due_at<?) "
            "ORDER BY t.claim_due_at,t.id",
            (now, now),
        ).fetchall())

    def task_detail(self, task_id: int) -> dict[str, Any]:
        task = self.repository.require_task(task_id)
        task["findings"] = self.repository.task_findings(task_id)
        return task

    def detail(self, opinion_id: int) -> dict[str, Any]:
        opinion = self.repository.require_opinion(opinion_id)
        opinion["versions"] = self._versions(opinion_id)
        opinion["tasks"] = records(self.connection.execute(
            "SELECT * FROM review_tasks WHERE opinion_id=? ORDER BY round_no,id", (opinion_id,)
        ).fetchall())
        findings = self.repository.opinion_findings(opinion_id)
        for finding in findings:
            finding["responses"] = self.repository.finding_responses(int(finding["id"]))
        opinion["findings"] = findings
        opinion["conflicts"] = self.repository.opinion_conflicts(opinion_id)
        opinion["timeline"] = self.timeline(opinion_id)
        return opinion

    def _versions(self, opinion_id: int) -> list[dict[str, Any]]:
        versions = records(self.connection.execute(
            "SELECT * FROM opinion_versions WHERE opinion_id=? ORDER BY version_no", (opinion_id,)
        ).fetchall())
        for version in versions:
            version["references"] = self.repository.version_references(int(version["id"]))
        return versions

    def timeline(self, opinion_id: int) -> dict[str, Any]:
        self.repository.require_opinion(opinion_id)
        events: list[dict[str, Any]] = []
        for version in records(self.connection.execute(
            "SELECT id,version_no,parent_version_id,content_hash,change_summary,submitted_by_name,created_at "
            "FROM opinion_versions WHERE opinion_id=? ORDER BY version_no", (opinion_id,)
        ).fetchall()):
            events.append({"at": version["created_at"], "type": "version", "data": version})
        for task in records(self.connection.execute(
            "SELECT * FROM review_tasks WHERE opinion_id=? ORDER BY id", (opinion_id,)
        ).fetchall()):
            if task["claimed_at"]:
                events.append({"at": task["claimed_at"], "type": "claim", "data": {
                    "task_id": task["id"], "round_no": task["round_no"],
                    "reviewer_id": task["reviewer_id"], "reviewer_name": task["reviewer_name"],
                }})
            if task["reassigned_at"]:
                events.append({"at": task["reassigned_at"], "type": "reassign", "data": {
                    "task_id": task["id"], "round_no": task["round_no"],
                    "reassigned_from_task_id": task["reassigned_from_task_id"],
                    "previous_reviewer_id": task["reviewer_id"],
                }})
            if task["completed_at"]:
                events.append({"at": task["completed_at"], "type": "review", "data": {
                    "task_id": task["id"], "round_no": task["round_no"], "result": task["result"],
                    "reviewer_name": task["reviewer_name"],
                }})
        for finding in records(self.connection.execute(
            "SELECT id,task_id,round_no,location_ref,severity,blocking,status,raised_by_name,created_at,resolution_note,"
            "resolved_by_name,resolved_at FROM review_findings WHERE opinion_id=? ORDER BY id", (opinion_id,)
        ).fetchall()):
            events.append({"at": finding["created_at"], "type": "finding", "data": {
                "finding_id": finding["id"], "severity": finding["severity"],
                "blocking": bool(finding["blocking"]), "location_ref": finding["location_ref"],
                "status": finding["status"], "raised_by": finding["raised_by_name"],
            }})
            if finding["resolved_at"]:
                events.append({"at": finding["resolved_at"], "type": "finding_closed", "data": {
                    "finding_id": finding["id"], "status": finding["status"],
                    "resolved_by": finding["resolved_by_name"], "note": finding["resolution_note"],
                }})
        for response in records(self.connection.execute(
            "SELECT r.id,r.finding_id,r.version_id,r.response_text,r.responded_by_name,r.created_at "
            "FROM finding_responses r JOIN review_findings f ON f.id=r.finding_id "
            "WHERE f.opinion_id=? ORDER BY r.id", (opinion_id,)
        ).fetchall()):
            events.append({"at": response["created_at"], "type": "revision_response", "data": response})
        # opinion_events 是只增审计日志；版本/领取/问题/复核/退修已由结构化记录还原，
        # 这里只补充没有独立结构化来源的事件。
        for domain_event in records(self.connection.execute(
            "SELECT event_type,actor_name,detail_json,created_at FROM opinion_events WHERE opinion_id=? "
            "AND event_type IN ('created','conflict_added','issued') ORDER BY id",
            (opinion_id,),
        ).fetchall()):
            events.append({"at": domain_event["created_at"], "type": domain_event["event_type"],
                           "data": {"actor": domain_event["actor_name"], **domain_event["detail"]}})
        events.sort(key=lambda item: (item["at"], item["type"]))

        opinion = self.repository.require_opinion(opinion_id)
        proof: dict[str, Any] | None = None
        if opinion["status"] == "issued" and opinion["issued_version_id"]:
            issued_version = self.repository.require_version(int(opinion["issued_version_id"]))
            refs, _ = self._reference_evidence(issued_version)
            proof = {
                "issued_version_id": issued_version["id"],
                "issued_version_no": issued_version["version_no"],
                "content_hash": issued_version["content_hash"],
                "approved_version_matches_issued": int(opinion["approved_version_id"]) == int(issued_version["id"]),
                "approval": record(self.connection.execute(
                    "SELECT id,reviewer_id,reviewer_name,completed_at,confirmed_sections_json FROM review_tasks "
                    "WHERE opinion_id=? AND version_id=? AND status='approved' ORDER BY completed_at DESC,id DESC LIMIT 1",
                    (opinion_id, issued_version["id"]),
                ).fetchone()),
                "references": refs,
                "issued_at": opinion["issued_at"], "issued_by_name": opinion["issued_by_name"],
            }
        return {"opinion_id": opinion_id, "status": opinion["status"], "events": events, "issuance_proof": proof}

    def _event(self, opinion_id: int, event_type: str, actor: dict[str, Any] | None, detail: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO opinion_events(opinion_id,event_type,actor_id,actor_name,detail_json,created_at) VALUES(?,?,?,?,?,?)",
            (
                opinion_id, event_type, actor["id"] if actor else None,
                actor["display_name"] if actor else "",
                json.dumps(detail, ensure_ascii=False, sort_keys=True, default=str), to_storage(self.clock.now()),
            ),
        )
