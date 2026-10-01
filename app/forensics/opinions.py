from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.forensics.repository import ForensicRepository, record, records

BLOCKING_SEVERITIES = {"blocking"}
ACTIVE_ASSIGNMENT_STATUSES = "('pool','open','claimed','reviewing')"


class OpinionReviewService:
    """鉴定意见签发前复核：不可覆盖版本、回避领取、退修与签发依据锚定。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    # ------------------------------------------------------------------ 复核人资质

    def register_reviewer(self, data: dict[str, Any]) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO reviewer_qualifications(reviewer,discipline,is_active,note,created_by,created_at,updated_at) "
                "VALUES(?,?,1,?,?,?,?)",
                (data["reviewer"], data["discipline"], data.get("note", ""), data["actor"], timestamp, timestamp),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("该复核人在此鉴定专业的资质登记已存在") from exc
        return self._qualification(int(cursor.lastrowid))

    def set_reviewer_status(self, qualification_id: int, active: bool) -> dict[str, Any]:
        self._qualification(qualification_id)
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE reviewer_qualifications SET is_active=?,updated_at=? WHERE id=?",
            (1 if active else 0, timestamp, qualification_id),
        )
        return self._qualification(qualification_id)

    def eligible_reviewers(self, opinion_id: int) -> list[dict[str, Any]]:
        opinion = self.require_opinion(opinion_id)
        return records(self.connection.execute(
            "SELECT * FROM reviewer_qualifications WHERE discipline=? AND is_active=1 AND reviewer<>? ORDER BY reviewer",
            (opinion["discipline"], opinion["produced_by"]),
        ).fetchall())

    def overdue_assignments(self) -> list[dict[str, Any]]:
        now = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT a.*,o.opinion_no,o.discipline,o.produced_by FROM review_assignments a "
            "JOIN appraisal_opinions o ON o.id=a.opinion_id "
            "WHERE a.status IN ('pool','open','claimed','reviewing') AND a.deadline_at IS NOT NULL "
            "AND a.deadline_at<? ORDER BY a.deadline_at",
            (now,),
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------ 意见与版本

    def create_opinion(self, data: dict[str, Any]) -> dict[str, Any]:
        forensic_case = self.repository.require_forensic_case(int(data["case_id"]))
        if forensic_case["status"] != "accepted":
            raise ConflictError("只有正式受理案件可以提交鉴定意见")
        examination = self.repository.require_examination(int(data["examination_id"]))
        specimen = self.repository.require_specimen(int(examination["specimen_id"]))
        if int(specimen["case_id"]) != int(forensic_case["id"]):
            raise ConflictError("检验任务不属于该案件")
        if examination["status"] != "completed":
            raise ConflictError("只有已完成且有效的检验可以形成鉴定意见",
                                context={"examination_status": examination["status"]})
        protocol = self.repository.require_protocol(int(examination["protocol_id"]))
        if protocol["discipline"] != forensic_case["discipline"]:
            raise ConflictError("检验规程的鉴定专业与案件不一致")
        if int(data.get("cited_protocol_id") or examination["protocol_id"]) != int(examination["protocol_id"]):
            raise ValidationError("声明的方法版本必须是该检验实际采用的规程版本")
        cited_specimens = sorted({int(value) for value in data.get("cited_specimen_ids", [])})
        cited_observations = sorted({int(value) for value in data.get("cited_observation_ids", [])})
        if not cited_specimens:
            raise ValidationError("提交鉴定意见必须声明所引用的检材")
        if not cited_observations:
            raise ValidationError("提交鉴定意见必须声明所引用的观察记录")
        self._validate_citations(int(forensic_case["id"]), int(examination["id"]), cited_specimens, cited_observations)
        timestamp = to_storage(self.clock.now())
        deadline = to_storage(self.clock.now() + timedelta(hours=int(data.get("deadline_hours", 72))))
        try:
            cursor = self.connection.execute(
                "INSERT INTO appraisal_opinions(opinion_no,case_id,examination_id,discipline,title,status,"
                "current_version_no,produced_by,due_at,version,created_at,updated_at) "
                "VALUES(?,?,?,?,?,'review',1,?,?,1,?,?)",
                (
                    data["opinion_no"], forensic_case["id"], examination["id"], forensic_case["discipline"],
                    data["title"], data["actor"], deadline, timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("鉴定意见编号已存在或该检验已有鉴定意见") from exc
        opinion_id = int(cursor.lastrowid)
        version = self._insert_version(
            opinion_id, 1, data, protocol, cited_specimens, cited_observations, data["actor"], timestamp
        )
        assignment_id = self._insert_assignment(opinion_id, 1, version["id"], version["version_no"],
                                                None, deadline, data["actor"], timestamp)
        self._event(opinion_id, "created", actor=data["actor"], detail={"title": data["title"]}, created_at=timestamp)
        self._event(opinion_id, "version_submitted", version_no=1, version_id=version["id"], actor=data["actor"],
                    detail={"content_hash": version["content_hash"]}, created_at=timestamp)
        self._event(opinion_id, "review_pooled", version_no=1, assignment_id=assignment_id, actor=data["actor"],
                    detail={"deadline_at": deadline}, created_at=timestamp)
        return self.opinion_detail(opinion_id)

    def add_revision(self, opinion_id: int, data: dict[str, Any]) -> dict[str, Any]:
        """退修产生新版本：版本不可变，已复核通过的旧版本与问题记录原样保留。"""
        opinion = self.require_opinion(opinion_id)
        if opinion["status"] != "revision":
            raise ConflictError("只有处于退修状态的意见可以形成新版本", context={"status": opinion["status"]})
        if data["actor"] != opinion["produced_by"]:
            raise ConflictError("只有原鉴定人可以提交退修版本")
        examination = self.repository.require_examination(int(opinion["examination_id"]))
        protocol = self.repository.require_protocol(int(examination["protocol_id"]))
        cited_specimens = sorted({int(value) for value in data.get("cited_specimen_ids", [])})
        cited_observations = sorted({int(value) for value in data.get("cited_observation_ids", [])})
        if not cited_specimens or not cited_observations:
            raise ValidationError("新版本必须重新声明所引用的检材和观察记录")
        self._validate_citations(int(opinion["case_id"]), int(opinion["examination_id"]),
                                 cited_specimens, cited_observations)
        timestamp = to_storage(self.clock.now())
        new_no = int(opinion["current_version_no"]) + 1
        version = self._insert_version(
            opinion_id, new_no, data, protocol, cited_specimens, cited_observations, data["actor"], timestamp
        )
        self.connection.execute(
            "UPDATE appraisal_opinions SET current_version_no=?,version=version+1,updated_at=? WHERE id=?",
            (new_no, timestamp, opinion_id),
        )
        self._event(opinion_id, "version_submitted", version_no=new_no, version_id=version["id"], actor=data["actor"],
                    detail={"content_hash": version["content_hash"], "change_note": data["change_note"]},
                    created_at=timestamp)
        return self.opinion_detail(opinion_id)

    def respond_finding(self, finding_id: int, data: dict[str, Any]) -> dict[str, Any]:
        finding = self._finding(finding_id)
        opinion = self.require_opinion(int(finding["opinion_id"]))
        if opinion["status"] != "revision":
            raise ConflictError("意见不在退修状态，不能处理问题")
        if data["actor"] != opinion["produced_by"]:
            raise ConflictError("只有原鉴定人可以回应退修问题")
        if finding["status"] not in {"open", "rejected"}:
            raise ConflictError("该问题已经回应，等待复核人确认")
        current = self._version_by_no(opinion["id"], int(opinion["current_version_no"]))
        if int(current["version_no"]) <= int(finding["version_no"]):
            raise ConflictError("处理退修意见必须先形成新报告版本")
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE review_findings SET status='resolved',resolution_note=?,resolved_by=?,resolved_at=?,"
            "resolution_version_id=?,updated_at=? WHERE id=?",
            (data["note"], data["actor"], timestamp, current["id"], timestamp, finding_id),
        )
        self._finding_event(finding_id, "responded", finding["status"], "resolved", data["note"], data["actor"],
                            timestamp, extra_detail={
                                "resolution_version_id": current["id"],
                                "resolution_version_no": current["version_no"],
                            })
        return self._finding(finding_id)

    def resubmit(self, opinion_id: int, data: dict[str, Any]) -> dict[str, Any]:
        opinion = self.require_opinion(opinion_id)
        if opinion["status"] != "revision":
            raise ConflictError("只有退修状态的意见可以重新送审")
        if data["actor"] != opinion["produced_by"]:
            raise ConflictError("只有原鉴定人可以重新送审")
        pending = [item for item in self.findings_for(opinion_id) if item["status"] in {"open", "rejected"}]
        if pending:
            raise ConflictError("仍有退修意见未逐条处理，不能重新送审", context={
                "pending_finding_ids": [item["id"] for item in pending],
            })
        timestamp = to_storage(self.clock.now())
        version = self._version_by_no(opinion_id, int(opinion["current_version_no"]))
        deadline = to_storage(self.clock.now() + timedelta(hours=int(data.get("deadline_hours", 72))))
        assignment_id = self._insert_assignment(
            opinion_id, self._next_sequence(opinion_id), version["id"], version["version_no"],
            None, deadline, data["actor"], timestamp
        )
        self.connection.execute(
            "UPDATE appraisal_opinions SET status='review',due_at=?,version=version+1,updated_at=? WHERE id=?",
            (deadline, timestamp, opinion_id),
        )
        self._event(opinion_id, "review_pooled", version_no=version["version_no"], assignment_id=assignment_id,
                    actor=data["actor"], detail={"deadline_at": deadline, "change_note": data.get("change_note", "")},
                    created_at=timestamp)
        return self.opinion_detail(opinion_id)

    # ------------------------------------------------------------------ 领取与复核

    def claim(self, opinion_id: int, reviewer: str) -> dict[str, Any]:
        opinion = self.require_opinion(opinion_id)
        if opinion["status"] != "review":
            raise ConflictError("该意见当前不在待复核状态", context={"status": opinion["status"]})
        assignment = self._active_assignment(opinion_id)
        if assignment is None:
            raise ConflictError("没有可领取的复核任务")
        reviewer = reviewer.strip()
        if reviewer == opinion["produced_by"]:
            raise ConflictError("鉴定人与复核人不得为同一人，应予回避")
        if not self._is_qualified(reviewer, opinion["discipline"]):
            raise ConflictError("复核人不具备该鉴定专业的有效复核资质或应回避")
        if assignment["status"] == "open" and assignment["reviewer"] != reviewer:
            raise ConflictError("该复核任务已指定其他复核人")
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE review_assignments SET status='claimed',claimed_by=?,claimed_at=?,reviewer=?,updated_at=? "
            "WHERE id=? AND status IN ('pool','open')",
            (reviewer, timestamp, reviewer, timestamp, assignment["id"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("该复核任务已被其他复核人领取")
        self._event(opinion_id, "claimed", assignment_id=assignment["id"], version_no=assignment["version_no"],
                    actor=reviewer, detail={"version_id": assignment["version_id"]}, created_at=timestamp)
        return self._assignment(int(assignment["id"]))

    def add_finding(self, opinion_id: int, reviewer: str, data: dict[str, Any]) -> dict[str, Any]:
        assignment = self._require_claimed(opinion_id, reviewer)
        next_no = int(self.connection.execute(
            "SELECT COALESCE(MAX(sequence_no),0)+1 FROM review_findings WHERE assignment_id=?", (assignment["id"],)
        ).fetchone()[0])
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO review_findings(assignment_id,opinion_id,version_id,version_no,sequence_no,location,"
            "severity,description,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'open',?,?,?)",
            (
                assignment["id"], opinion_id, assignment["version_id"], assignment["version_no"], next_no,
                data["location"], data["severity"], data["description"], reviewer, timestamp, timestamp,
            ),
        )
        finding_id = int(cursor.lastrowid)
        self.connection.execute(
            "UPDATE review_assignments SET status='reviewing',updated_at=? WHERE id=?", (timestamp, assignment["id"])
        )
        self._finding_event(finding_id, "raised", None, "open", data["description"], reviewer, timestamp,
                            extra_detail={"location": data["location"], "severity": data["severity"]})
        return self._finding(finding_id)

    def close_finding(self, finding_id: int, reviewer: str, accept: bool, note: str) -> dict[str, Any]:
        finding = self._finding(finding_id)
        assignment = self._require_claimed(int(finding["opinion_id"]), reviewer)
        timestamp = to_storage(self.clock.now())
        active_version_no = int(self.require_opinion(int(finding["opinion_id"]))["current_version_no"])
        overrides = {
            "assignment_override_id": int(assignment["id"]),
            "version_override_no": active_version_no,
        }
        if accept:
            if finding["status"] == "resolved":
                self.connection.execute(
                    "UPDATE review_findings SET status='accepted',"
                    "resolution_note=COALESCE(NULLIF(resolution_note,''),?),updated_at=? WHERE id=?",
                    (note, timestamp, finding_id),
                )
                self._finding_event(finding_id, "closed", finding["status"], "accepted", note, reviewer,
                                    timestamp, **overrides)
            elif finding["status"] == "open" and int(finding["assignment_id"]) == int(assignment["id"]):
                # 复核人在鉴定人回应前撤回自己误提的问题，仍记录处理结论
                self.connection.execute(
                    "UPDATE review_findings SET status='accepted',resolution_note=?,resolved_by=?,resolved_at=?,"
                    "updated_at=? WHERE id=?",
                    (note, reviewer, timestamp, timestamp, finding_id),
                )
                self._finding_event(finding_id, "closed", "open", "accepted", note, reviewer,
                                    timestamp, **overrides)
            else:
                raise ConflictError("当前问题状态不能确认关闭")
        else:
            if finding["status"] != "resolved":
                raise ConflictError("只有鉴定人已回应处理的问题可以驳回")
            self.connection.execute(
                "UPDATE review_findings SET status='open',updated_at=? WHERE id=?", (timestamp, finding_id)
            )
            self._finding_event(finding_id, "reopened", "resolved", "open", note, reviewer,
                                timestamp, **overrides)
        return self._finding(finding_id)

    def decide_review(self, opinion_id: int, data: dict[str, Any]) -> dict[str, Any]:
        assignment = self._require_claimed(opinion_id, data["reviewer"])
        opinion = self.require_opinion(opinion_id)
        timestamp = to_storage(self.clock.now())
        findings = self.findings_for(opinion_id)
        if data["approve"]:
            pending = [item for item in findings if item["status"] != "accepted"]
            if pending:
                raise ConflictError("仍有问题未确认关闭，不能复核通过", context={
                    "pending_finding_ids": [item["id"] for item in pending],
                })
            self._complete_assignment(assignment, "approved", timestamp, data.get("note", ""))
            self.connection.execute(
                "UPDATE appraisal_opinions SET status='approved',approved_version_id=?,version=version+1,updated_at=? "
                "WHERE id=?",
                (assignment["version_id"], timestamp, opinion_id),
            )
            version = self._version_by_id(int(assignment["version_id"]))
            self._event(opinion_id, "review_approved", assignment_id=assignment["id"],
                        version_no=version["version_no"], version_id=version["id"], actor=data["reviewer"],
                        detail={"content_hash": version["content_hash"]}, created_at=timestamp)
        else:
            if not findings or all(item["status"] == "accepted" for item in findings):
                raise ConflictError("退修必须至少提出一条未关闭问题")
            self._complete_assignment(assignment, "returned", timestamp, data.get("note", ""))
            self.connection.execute(
                "UPDATE appraisal_opinions SET status='revision',version=version+1,updated_at=? WHERE id=?",
                (timestamp, opinion_id),
            )
            self._event(opinion_id, "review_returned", assignment_id=assignment["id"],
                        version_no=assignment["version_no"], actor=data["reviewer"],
                        detail={"note": data.get("note", ""),
                                "blocking_finding_ids": [item["id"] for item in findings
                                                         if item["severity"] in BLOCKING_SEVERITIES
                                                         and item["status"] != "accepted"]},
                        created_at=timestamp)
        return self.opinion_detail(opinion_id)

    # ------------------------------------------------------------------ 改派与签发

    def reassign_overdue(self, opinion_id: int, data: dict[str, Any]) -> dict[str, Any]:
        opinion = self.require_opinion(opinion_id)
        if opinion["status"] != "review":
            raise ConflictError("只有待复核意见可以改派", context={"status": opinion["status"]})
        assignment = self._active_assignment(opinion_id)
        if assignment is None:
            raise ConflictError("没有进行中的复核任务")
        if not assignment["deadline_at"]:
            raise ConflictError("该复核任务没有期限，不能按逾期改派")
        if from_storage(assignment["deadline_at"]) > self.clock.now():
            raise ConflictError("复核任务尚未逾期，不能改派", context={"deadline_at": assignment["deadline_at"]})
        designated = (data.get("reviewer") or "").strip() or None
        if designated:
            if designated == opinion["produced_by"]:
                raise ConflictError("鉴定人与复核人不得为同一人，应予回避")
            if not self._is_qualified(designated, opinion["discipline"]):
                raise ConflictError("指定复核人不具备该鉴定专业的有效复核资质")
        timestamp = to_storage(self.clock.now())
        new_deadline = to_storage(self.clock.now() + timedelta(hours=int(data["deadline_hours"])))
        new_id = self._insert_assignment(
            opinion_id, self._next_sequence(opinion_id), int(assignment["version_id"]),
            int(assignment["version_no"]), designated, new_deadline, data["actor"], timestamp,
        )
        self.connection.execute(
            "UPDATE review_assignments SET status='expired_reassigned',reassignment_reason=?,reassigned_by=?,"
            "superseded_by_assignment_id=?,version=version+1,updated_at=? WHERE id=?",
            (data["reason"], data["actor"], new_id, timestamp, assignment["id"]),
        )
        self.connection.execute(
            "UPDATE appraisal_opinions SET due_at=?,version=version+1,updated_at=? WHERE id=?",
            (new_deadline, timestamp, opinion_id),
        )
        self._event(opinion_id, "review_reassigned", assignment_id=new_id,
                    version_no=assignment["version_no"], actor=data["actor"],
                    detail={"previous_assignment_id": assignment["id"],
                            "previous_claimed_by": assignment["claimed_by"],
                            "reason": data["reason"], "reviewer": designated,
                            "deadline_at": new_deadline}, created_at=timestamp)
        return self.opinion_detail(opinion_id)

    def issue(self, opinion_id: int, data: dict[str, Any]) -> dict[str, Any]:
        opinion = self.require_opinion(opinion_id)
        if int(opinion["version"]) != int(data["expected_version"]):
            raise ConflictError("鉴定意见版本冲突", context={"current_version": opinion["version"]})
        if opinion["status"] != "approved":
            raise ConflictError("只有复核通过的意见可以签发", context={"status": opinion["status"]})
        if not opinion["approved_version_id"]:
            raise ConflictError("缺少复核通过的版本锚点，不能签发")
        findings = self.findings_for(opinion_id)
        blocking_open = [item for item in findings
                         if item["severity"] in BLOCKING_SEVERITIES and item["status"] != "accepted"]
        if blocking_open:
            raise ConflictError("存在未关闭的阻断意见，不能签发", context={
                "blocking_finding_ids": [item["id"] for item in blocking_open],
            })
        version = self._version_by_id(int(opinion["approved_version_id"]))
        if self._recompute_hash(version) != version["content_hash"]:
            raise ConflictError("复核通过版本的内容哈希校验失败，版本可能已被改写")
        examination = self.repository.require_examination(int(opinion["examination_id"]))
        if examination["status"] != "completed":
            raise ConflictError("签发时所引检验已不再有效", context={"examination_status": examination["status"]})
        cited_observation_ids = version["cited_observation_ids"]
        if cited_observation_ids:
            placeholders = ",".join("?" for _ in cited_observation_ids)
            valid_count = int(self.connection.execute(
                f"SELECT COUNT(*) FROM examination_observations WHERE id IN ({placeholders}) AND examination_id=?",
                (*cited_observation_ids, opinion["examination_id"]),
            ).fetchone()[0])
            if valid_count != len(cited_observation_ids):
                raise ConflictError("签发时所引观察记录已失效或不属于该检验")
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO opinion_issuances(opinion_id,version_id,content_hash,issued_by,issued_at,basis_note) "
                "VALUES(?,?,?,?,?,?)",
                (opinion_id, version["id"], version["content_hash"], data["actor"], timestamp, data.get("note", "")),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("鉴定意见只能签发一次") from exc
        self.connection.execute(
            "UPDATE appraisal_opinions SET status='issued',issued_at=?,version=version+1,updated_at=? WHERE id=?",
            (timestamp, timestamp, opinion_id),
        )
        self._event(opinion_id, "issued", version_no=version["version_no"], version_id=version["id"],
                    actor=data["actor"],
                    detail={"issuance_id": cursor.lastrowid, "content_hash": version["content_hash"],
                            "basis": "issued_version_equals_approved_version",
                            "examination_id": opinion["examination_id"],
                            "examination_status_at_issue": examination["status"],
                            "cited_protocol_id": version["cited_protocol_id"],
                            "cited_protocol_version": version["cited_protocol_version"],
                            "blocking_findings_closed": True}, created_at=timestamp)
        return self.opinion_detail(opinion_id)

    # ------------------------------------------------------------------ 查询与时间线

    def require_opinion(self, opinion_id: int) -> dict[str, Any]:
        item = record(self.connection.execute(
            "SELECT * FROM appraisal_opinions WHERE id=?", (opinion_id,)
        ).fetchone())
        if item is None:
            raise NotFoundError("鉴定意见不存在")
        return item

    def opinion_detail(self, opinion_id: int) -> dict[str, Any]:
        opinion = self.require_opinion(opinion_id)
        opinion["versions"] = [self._version_row(row) for row in self.connection.execute(
            "SELECT * FROM opinion_versions WHERE opinion_id=? ORDER BY version_no", (opinion_id,)
        ).fetchall()]
        opinion["assignments"] = [dict(row) for row in self.connection.execute(
            "SELECT * FROM review_assignments WHERE opinion_id=? ORDER BY sequence_no", (opinion_id,)
        ).fetchall()]
        opinion["findings"] = [dict(row) for row in self.connection.execute(
            "SELECT * FROM review_findings WHERE opinion_id=? ORDER BY id", (opinion_id,)
        ).fetchall()]
        issuance = self.connection.execute(
            "SELECT * FROM opinion_issuances WHERE opinion_id=?", (opinion_id,)
        ).fetchone()
        opinion["issuance"] = dict(issuance) if issuance else None
        return opinion

    def timeline(self, opinion_id: int) -> dict[str, Any]:
        opinion = self.opinion_detail(opinion_id)
        # 主流水按插入顺序同时承载主流程事件与问题生命周期事件
        events = [self._journal_row(row) for row in self.connection.execute(
            "SELECT * FROM opinion_journal WHERE opinion_id=? ORDER BY created_at,id", (opinion_id,)
        ).fetchall()]
        finding_events = []
        for row in self.connection.execute(
            "SELECT e.id,e.finding_id,e.event_type,e.from_status,e.to_status,e.note,e.actor,e.created_at,"
            "f.opinion_id,f.assignment_id,f.version_no FROM review_finding_events e "
            "JOIN review_findings f ON f.id=e.finding_id WHERE f.opinion_id=? ORDER BY e.created_at,e.id",
            (opinion_id,),
        ).fetchall():
            item = self._journal_row(row)
            item["event_type"] = f"finding_{item['event_type']}"
            finding_events.append(item)
        proof = None
        if opinion["issuance"]:
            approved = next((v for v in opinion["versions"] if v["id"] == opinion["approved_version_id"]), None)
            issuance = opinion["issuance"]
            proof = {
                "issued_version_id": issuance["version_id"],
                "issued_version_no": approved["version_no"] if approved else None,
                "approved_version_id": opinion["approved_version_id"],
                "version_match": issuance["version_id"] == opinion["approved_version_id"],
                "issued_content_hash": issuance["content_hash"],
                "approved_content_hash": approved["content_hash"] if approved else None,
                "hash_match": bool(approved) and issuance["content_hash"] == approved["content_hash"],
                "recomputed_hash_match": bool(approved) and self._recompute_hash(approved) == approved["content_hash"],
                "basis": "签发记录的版本标识与内容哈希均等同于复核通过锚点",
            }
        return {
            "opinion": {k: v for k, v in opinion.items()
                        if k not in {"versions", "assignments", "findings", "issuance"}},
            "versions": opinion["versions"],
            "assignments": opinion["assignments"],
            "findings": opinion["findings"],
            "finding_events": finding_events,
            "issuance": opinion["issuance"],
            "events": events,
            "timeline": events,
            "issuance_proof": proof,
        }

    def findings_for(self, opinion_id: int) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM review_findings WHERE opinion_id=? ORDER BY id", (opinion_id,)
        ).fetchall()]

    # ------------------------------------------------------------------ 内部辅助

    def _is_qualified(self, reviewer: str, discipline: str) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM reviewer_qualifications WHERE reviewer=? AND discipline=? AND is_active=1",
            (reviewer, discipline),
        ).fetchone() is not None

    def _validate_citations(
        self, case_id: int, examination_id: int, specimen_ids: list[int], observation_ids: list[int]
    ) -> None:
        for specimen_id in specimen_ids:
            row = self.connection.execute("SELECT case_id FROM specimens WHERE id=?", (specimen_id,)).fetchone()
            if row is None:
                raise ValidationError(f"引用检材不存在：{specimen_id}")
            if int(row[0]) != case_id:
                raise ValidationError(f"引用检材 {specimen_id} 不属于本案件")
        for observation_id in observation_ids:
            row = self.connection.execute(
                "SELECT examination_id FROM examination_observations WHERE id=?", (observation_id,)
            ).fetchone()
            if row is None:
                raise ValidationError(f"引用观察记录不存在：{observation_id}")
            if int(row[0]) != examination_id:
                raise ValidationError(f"引用观察记录 {observation_id} 不属于所引检验")

    def _insert_version(
        self, opinion_id: int, version_no: int, data: dict[str, Any], protocol: dict[str, Any],
        specimen_ids: list[int], observation_ids: list[int], actor: str, timestamp: str,
    ) -> dict[str, Any]:
        content_hash = self._compute_hash(
            opinion_id, version_no, data["body"], specimen_ids, observation_ids,
            int(protocol["id"]), int(protocol["version"]),
        )
        cursor = self.connection.execute(
            "INSERT INTO opinion_versions(opinion_id,version_no,body,content_hash,cited_specimen_ids_json,"
            "cited_observation_ids_json,cited_protocol_id,cited_protocol_version,declaration_note,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                opinion_id, version_no, data["body"], content_hash, json.dumps(specimen_ids),
                json.dumps(observation_ids), int(protocol["id"]), int(protocol["version"]),
                data.get("declaration_note", ""), actor, timestamp,
            ),
        )
        return self._version_by_id(int(cursor.lastrowid))

    def _insert_assignment(
        self, opinion_id: int, sequence_no: int, version_id: int, version_no: int, reviewer: str | None,
        deadline_at: str, created_by: str, timestamp: str,
    ) -> int:
        status = "open" if reviewer else "pool"
        cursor = self.connection.execute(
            "INSERT INTO review_assignments(opinion_id,sequence_no,version_id,version_no,reviewer,status,deadline_at,"
            "created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (opinion_id, sequence_no, version_id, version_no, reviewer, status, deadline_at,
             created_by, timestamp, timestamp),
        )
        return int(cursor.lastrowid)

    def _complete_assignment(self, assignment: dict[str, Any], decision: str, timestamp: str, note: str) -> None:
        self.connection.execute(
            "UPDATE review_assignments SET status=?,completed_at=?,review_decision=?,review_note=?,"
            "version=version+1,updated_at=? WHERE id=?",
            ("completed" if decision == "approved" else "returned", timestamp, decision, note,
             timestamp, assignment["id"]),
        )

    def _active_assignment(self, opinion_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            f"SELECT * FROM review_assignments WHERE opinion_id=? AND status IN {ACTIVE_ASSIGNMENT_STATUSES} "
            "ORDER BY sequence_no DESC LIMIT 1",
            (opinion_id,),
        ).fetchone()
        return dict(row) if row else None

    def _require_claimed(self, opinion_id: int, reviewer: str) -> dict[str, Any]:
        self.require_opinion(opinion_id)
        assignment = self._active_assignment(opinion_id)
        if assignment is None or assignment["claimed_by"] != reviewer:
            raise ConflictError("只有已领取该任务的复核人可以操作")
        if assignment["status"] not in {"claimed", "reviewing"}:
            raise ConflictError("当前领取状态不能执行复核操作")
        return assignment

    def _next_sequence(self, opinion_id: int) -> int:
        return int(self.connection.execute(
            "SELECT COALESCE(MAX(sequence_no),0)+1 FROM review_assignments WHERE opinion_id=?", (opinion_id,)
        ).fetchone()[0])

    @staticmethod
    def _compute_hash(
        opinion_id: int, version_no: int, body: str, specimen_ids: list[int], observation_ids: list[int],
        protocol_id: int, protocol_version: int,
    ) -> str:
        payload = json.dumps({
            "opinion_id": opinion_id,
            "version_no": version_no,
            "body": body,
            "specimens": specimen_ids,
            "observations": observation_ids,
            "protocol_id": protocol_id,
            "protocol_version": protocol_version,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _recompute_hash(self, version: dict[str, Any]) -> str:
        return self._compute_hash(
            int(version["opinion_id"]), int(version["version_no"]), version["body"],
            version["cited_specimen_ids"], version["cited_observation_ids"],
            int(version["cited_protocol_id"]), int(version["cited_protocol_version"]),
        )

    def _event(
        self, opinion_id: int, event_type: str, *, actor: str = "", version_no: int | None = None,
        version_id: int | None = None, assignment_id: int | None = None, finding_id: int | None = None,
        detail: dict[str, Any] | None = None, created_at: str | None = None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO opinion_journal(opinion_id,event_type,version_no,version_id,assignment_id,finding_id,"
            "actor,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (opinion_id, event_type, version_no, version_id, assignment_id, finding_id, actor,
             json.dumps(detail or {}, ensure_ascii=False), created_at or to_storage(self.clock.now())),
        )

    def _finding_event(
        self, finding_id: int, event_type: str, from_status: str | None, to_status: str,
        note: str, actor: str, timestamp: str, extra_detail: dict[str, Any] | None = None,
        assignment_override_id: int | None = None, version_override_no: int | None = None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO review_finding_events(finding_id,event_type,from_status,to_status,note,actor,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (finding_id, event_type, from_status, to_status, note, actor, timestamp),
        )
        row = self.connection.execute(
            "SELECT opinion_id,assignment_id,version_no FROM review_findings WHERE id=?", (finding_id,)
        ).fetchone()
        detail = {"from_status": from_status, "to_status": to_status, "note": note}
        if extra_detail:
            detail.update(extra_detail)
        assignment_id = assignment_override_id or row["assignment_id"]
        version_no = version_override_no if version_override_no is not None else row["version_no"]
        # 同步写入意见主流水，保证时间线里问题生命周期事件与主流程事件因果有序
        self.connection.execute(
            "INSERT INTO opinion_journal(opinion_id,event_type,version_no,assignment_id,finding_id,actor,"
            "detail_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                row["opinion_id"], f"finding_{event_type}", version_no, assignment_id, finding_id,
                actor, json.dumps(detail, ensure_ascii=False), timestamp,
            ),
        )

    def _qualification(self, qualification_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM reviewer_qualifications WHERE id=?", (qualification_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("复核人资质登记不存在")
        return dict(row)

    def _version_by_id(self, version_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM opinion_versions WHERE id=?", (version_id,)).fetchone()
        if row is None:
            raise NotFoundError("报告版本不存在")
        return self._version_row(row)

    def _version_by_no(self, opinion_id: int, version_no: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM opinion_versions WHERE opinion_id=? AND version_no=?", (opinion_id, version_no)
        ).fetchone()
        if row is None:
            raise NotFoundError("报告版本不存在")
        return self._version_row(row)

    @staticmethod
    def _version_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["cited_specimen_ids"] = json.loads(item.pop("cited_specimen_ids_json") or "[]")
        item["cited_observation_ids"] = json.loads(item.pop("cited_observation_ids_json") or "[]")
        return item

    def _assignment(self, assignment_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM review_assignments WHERE id=?", (assignment_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("复核任务不存在")
        return dict(row)

    def _finding(self, finding_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM review_findings WHERE id=?", (finding_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("复核问题不存在")
        return dict(row)

    @staticmethod
    def _journal_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        if "detail_json" in item:
            raw = item.pop("detail_json")
            try:
                item["detail"] = json.loads(raw or "{}")
            except json.JSONDecodeError:
                item["detail"] = {}
        elif "detail" not in item:
            item["detail"] = {}
        return item
