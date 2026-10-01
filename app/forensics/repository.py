from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from app.core.errors import NotFoundError


JSON_COLUMNS = {
    "case_profile_json": "passport",
    "contact_json": "restrictions",
    "detail_json": "detail",
    "payload_json": "payload",
    "report_sections_json": "sections",
    "issue_evidence_json": "issue_evidence",
    "confirmed_sections_json": "confirmed_sections",
    "snapshot_json": "snapshot",
}


def record(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    for column, target in JSON_COLUMNS.items():
        if column in data:
            raw = data.pop(column)
            try:
                data[target] = json.loads(raw or "{}")
            except json.JSONDecodeError:
                data[target] = {}
    return data


def records(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [record(row) or {} for row in rows]


class ForensicRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def require_agency(self, agency_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM submitting_agencies WHERE id=?", (agency_id,)).fetchone())
        if item is None:
            raise NotFoundError("来源记录不存在")
        return item

    def require_forensic_case(self, case_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM forensic_cases WHERE id=?", (case_id,)).fetchone())
        if item is None:
            raise NotFoundError("鉴定案件不存在")
        return item

    def forensic_case_by_number(self, case_no: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM forensic_cases WHERE case_no=?", (case_no,)).fetchone())

    def forensic_case_detail(self, case_id: int) -> dict[str, Any]:
        item = self.require_forensic_case(case_id)
        if item.get("agency_id"):
            item["source"] = self.require_agency(int(item["agency_id"]))
        item["lots"] = records(self.connection.execute(
            "SELECT * FROM specimens WHERE case_id=? ORDER BY created_at,specimen_no", (case_id,)
        ).fetchall())
        item["events"] = records(self.connection.execute(
            "SELECT * FROM case_events WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall())
        return item

    def list_forensic_cases(self, *, status: str | None, crop: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status=?")
            params.append(status)
        if crop:
            where.append("discipline LIKE ?")
            params.append(f"%{crop.strip()}%")
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM forensic_cases{clause}", params).fetchone()[0])
        params.extend([limit, offset])
        rows = self.connection.execute(
            f"SELECT * FROM forensic_cases{clause} ORDER BY accepted_on DESC,case_no LIMIT ? OFFSET ?", params
        ).fetchall()
        return records(rows), total

    def require_location(self, location_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM storage_locations WHERE id=?", (location_id,)).fetchone())
        if item is None:
            raise NotFoundError("库位不存在")
        return item

    def location_usage(self, location_id: int) -> float:
        row = self.connection.execute(
            "SELECT COALESCE(SUM(quantity),0) FROM specimen_placements WHERE location_id=? AND removed_at IS NULL",
            (location_id,),
        ).fetchone()
        return float(row[0])

    def location_detail(self, location_id: int) -> dict[str, Any]:
        item = self.require_location(location_id)
        item["used_grams"] = self.location_usage(location_id)
        item["available_grams"] = round(float(item["capacity_units"]) - item["used_grams"], 6)
        item["placements"] = records(self.connection.execute(
            "SELECT p.*,l.specimen_no FROM specimen_placements p JOIN specimens l ON l.id=p.specimen_id "
            "WHERE p.location_id=? AND p.removed_at IS NULL ORDER BY p.container_code", (location_id,)
        ).fetchall())
        return item

    def require_specimen(self, specimen_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM specimens WHERE id=?", (specimen_id,)).fetchone())
        if item is None:
            raise NotFoundError("检材不存在")
        return item

    def active_holds(self, specimen_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM specimen_holds WHERE specimen_id=? AND released_at IS NULL ORDER BY id", (specimen_id,)
        ).fetchall())

    def specimen_detail(self, specimen_id: int) -> dict[str, Any]:
        item = self.require_specimen(specimen_id)
        item["forensic_case"] = self.require_forensic_case(int(item["case_id"]))
        item["placements"] = records(self.connection.execute(
            "SELECT p.*,s.location_code FROM specimen_placements p JOIN storage_locations s ON s.id=p.location_id "
            "WHERE p.specimen_id=? ORDER BY p.id", (specimen_id,)
        ).fetchall())
        item["movements"] = records(self.connection.execute(
            "SELECT * FROM custody_events WHERE specimen_id=? ORDER BY id", (specimen_id,)
        ).fetchall())
        item["holds"] = records(self.connection.execute(
            "SELECT * FROM specimen_holds WHERE specimen_id=? ORDER BY id", (specimen_id,)
        ).fetchall())
        item["latest_examination"] = record(self.connection.execute(
            "SELECT * FROM examinations WHERE specimen_id=? AND status='completed' ORDER BY completed_at DESC,id DESC LIMIT 1",
            (specimen_id,),
        ).fetchone())
        return item

    def require_placement(self, placement_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM specimen_placements WHERE id=?", (placement_id,)).fetchone())
        if item is None:
            raise NotFoundError("容器摆放记录不存在")
        return item

    def custody_event_by_key(self, key: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM custody_events WHERE idempotency_key=?", (key,)).fetchone())

    def require_protocol(self, protocol_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM examination_protocols WHERE id=?", (protocol_id,)).fetchone())
        if item is None:
            raise NotFoundError("检验规程不存在")
        return item

    def protocol_latest(self, code: str) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM examination_protocols WHERE protocol_code=? ORDER BY version DESC LIMIT 1", (code,)
        ).fetchone())

    def require_examination(self, examination_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM examinations WHERE id=?", (examination_id,)).fetchone())
        if item is None:
            raise NotFoundError("检验任务不存在")
        return item

    def examination_detail(self, examination_id: int) -> dict[str, Any]:
        item = self.require_examination(examination_id)
        item["specimen"] = self.require_specimen(int(item["specimen_id"]))
        item["protocol"] = self.require_protocol(int(item["protocol_id"]))
        item["counts"] = records(self.connection.execute(
            "SELECT * FROM examination_observations WHERE examination_id=? ORDER BY checkpoint_no,sequence_no", (examination_id,)
        ).fetchall())
        return item

    def require_policy(self, policy_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM review_policies WHERE id=?", (policy_id,)).fetchone())
        if item is None:
            raise NotFoundError("复核策略不存在")
        return item

    def applicable_policy(self, discipline: str, risk_level: str, on_date: str) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM review_policies WHERE discipline=? AND risk_level=? AND effective_from<=? "
            "AND (effective_to IS NULL OR effective_to>=?) ORDER BY version DESC LIMIT 1",
            (discipline, risk_level, on_date, on_date),
        ).fetchone())

    def require_alert(self, alert_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM quality_alerts WHERE id=?", (alert_id,)).fetchone())
        if item is None:
            raise NotFoundError("质量告警不存在")
        return item

    def require_release(self, request_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM release_requests WHERE id=?", (request_id,)).fetchone())
        if item is None:
            raise NotFoundError("领用申请不存在")
        return item

    def release_detail(self, request_id: int) -> dict[str, Any]:
        item = self.require_release(request_id)
        item["items"] = records(self.connection.execute(
            "SELECT i.*,a.case_no,a.discipline FROM release_items i "
            "JOIN forensic_cases a ON a.id=i.case_id WHERE i.request_id=? ORDER BY i.id", (request_id,)
        ).fetchall())
        return item

    def count_table(self, table: str) -> int:
        allowed = {
            "forensic_cases", "specimens", "storage_locations", "examinations",
            "review_schedules", "quality_alerts", "release_requests", "expert_opinions",
            "opinion_versions", "review_tasks", "review_findings",
        }
        if table not in allowed:
            raise ValueError("不允许统计该数据表")
        return int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def require_opinion(self, opinion_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM expert_opinions WHERE id=?", (opinion_id,)).fetchone())
        if item is None:
            raise NotFoundError("鉴定意见不存在")
        return item

    def opinion_by_number(self, opinion_no: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM expert_opinions WHERE opinion_no=?", (opinion_no,)).fetchone())

    def require_version(self, version_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM opinion_versions WHERE id=?", (version_id,)).fetchone())
        if item is None:
            raise NotFoundError("报告版本不存在")
        return item

    def opinion_version(self, opinion_id: int, version_no: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM opinion_versions WHERE opinion_id=? AND version_no=?", (opinion_id, version_no)
        ).fetchone())

    def latest_version(self, opinion_id: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM opinion_versions WHERE opinion_id=? ORDER BY version_no DESC LIMIT 1", (opinion_id,)
        ).fetchone())

    def version_references(self, version_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM opinion_version_references WHERE version_id=? ORDER BY ref_type,id", (version_id,)
        ).fetchall())

    def require_task(self, task_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM review_tasks WHERE id=?", (task_id,)).fetchone())
        if item is None:
            raise NotFoundError("复核任务不存在")
        return item

    def opinion_active_task(self, opinion_id: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM review_tasks WHERE opinion_id=? AND status IN ('pending','claimed') ORDER BY id DESC LIMIT 1",
            (opinion_id,),
        ).fetchone())

    def require_finding(self, finding_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM review_findings WHERE id=?", (finding_id,)).fetchone())
        if item is None:
            raise NotFoundError("复核问题不存在")
        return item

    def opinion_findings(self, opinion_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM review_findings WHERE opinion_id=? ORDER BY round_no,id", (opinion_id,)
        ).fetchall())

    def task_findings(self, task_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM review_findings WHERE task_id=? ORDER BY id", (task_id,)
        ).fetchall())

    def finding_responses(self, finding_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM finding_responses WHERE finding_id=? ORDER BY version_id,id", (finding_id,)
        ).fetchall())

    def opinion_conflicts(self, opinion_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT c.*,u.username,u.display_name FROM opinion_conflicts c "
            "JOIN users u ON u.id=c.user_id WHERE c.opinion_id=? ORDER BY c.user_id", (opinion_id,)
        ).fetchall())

    def user_permissions(self, user_id: int) -> set[str]:
        rows = self.connection.execute(
            "SELECT DISTINCT p.code FROM permissions p "
            "JOIN role_permissions rp ON rp.permission_id=p.id "
            "JOIN user_roles ur ON ur.role_id=rp.role_id WHERE ur.user_id=?",
            (user_id,),
        ).fetchall()
        return {str(row[0]) for row in rows}

    def require_user(self, user_id: int) -> dict[str, Any]:
        item = record(self.connection.execute(
            "SELECT id,username,display_name,department_id,status FROM users WHERE id=?", (user_id,)
        ).fetchone())
        if item is None:
            raise NotFoundError("用户不存在")
        return item
