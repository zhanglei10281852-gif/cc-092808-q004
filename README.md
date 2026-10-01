# 司法鉴定检材流转与复核服务

本项目是面向司法鉴定机构的 Python 后端服务，用于登记委托或移送案件、接收带封识的检材、记录保管位置与流转、执行专业检验、安排复核并处理环境和质量告警。案件、检材、检验记录和领用审批都保存在本地 SQLite 中，关键写入带版本或幂等键，适合在单个 Linux 应用容器内运行。

## 运行环境

- Python 3.11
- FastAPI 与 Uvicorn
- SQLite 3，由 Python 标准库提供

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `data/forensics.db`，也可以通过 `FORENSICS_DATABASE_PATH` 指向其他 `.db`、`.sqlite` 或 `.sqlite3` 文件。

## 初始化与启动

```bash
python -m app.cli init-db
python -m app.cli check-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查为 `GET /api/system/health`。首次使用可调用 `POST /api/auth/bootstrap` 创建管理员，再通过 `POST /api/auth/login` 取得 Bearer 会话令牌。鉴定业务接口统一位于 `/api/forensics`。

## 测试与构建检查

```bash
python -m pytest
python -m compileall -q app tests
```

下面两条命令分别检查 HTTP 入口和完整的入库演示链路：

```bash
python -m app.cli smoke
python -m app.cli demo
```

## 业务边界

- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料与受理状态。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/forensics/opinions.py` 管理鉴定意见的不可覆盖报告版本、回避领取、退修闭环、复核结论与签发留证。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 签发前复核流程

鉴定意见不能仅凭口头确认标记完成。一条意见必须经过「提交不可覆盖版本 → 符合回避要求的复核人领取 → 提出带定位和严重程度的问题 → 退修形成新版本并逐条处理 → 复核通过 → 签发留证」的闭环：

1. 鉴定人（`technician`，`opinion.write`）`POST /api/forensics/opinions` 创建意见，再 `POST /opinions/{id}/versions` 提交版本。正文按章节结构化存储并计算 `content_hash`，版本只增不改；每次提交必须声明所引用的检材、观察记录和检验规程（方法）版本，引用必须属于本案、专业匹配且当前有效。
2. 提交后生成待领取复核任务。复核人（`curator`，`opinion.review`）从 `GET /review-tasks/pending` 查看自己可领取的任务，并经 `POST /review-tasks/{id}/claim` 领取。领取用条件更新配合部分唯一索引保证并发只能成功一次；鉴定人本人、被列入回避名单（`POST /opinions/{id}/conflicts`）或无复核权限的账号不能领取。
3. 复核人通过 `POST /review-tasks/{id}/findings` 提出问题，每条问题必须有章节定位（`location_ref`）、严重程度（`minor/major/critical`）、处理要求（`must_revise/explain/note`）和阻断标记（major/critical 或 must_revise 自动阻断）。`POST /review-tasks/{id}/decision` 给出通过或退修结论，并可记录本轮已逐字复核确认的章节。
4. 退修后鉴定人必须再提交新版本（`version_no` 递增、保留父版本指针），并对每条开放问题逐条回应。历轮已确认章节必须逐字保留，不能随正文一起被改写。阻断问题未全部关闭不得复核通过。
5. 质量负责人（`quality_manager`，`opinion.dispatch`/`opinion.issue`）可对逾期未领取或逾期未结论的任务 `POST /review-tasks/{id}/reassign` 重新分派：旧任务标记为 `reassigned` 并保留原领取人，新任务通过 `reassigned_from_task_id` 指回，责任链不被抹去。
6. 复核通过后意见进入 `review_passed`。签发 `POST /opinions/{id}/issue` 时再次确认：所有阻断意见已关闭、最终版本就是复核通过版本、所引检材/观察记录/方法版本此刻仍有效。签发记录确切版本号、内容摘要、批准任务和引用快照。
7. `GET /opinions/{id}/timeline` 按时间还原版本提交、领取、回避、问题提出、退修回应、问题关闭、复核结论、重新分派和签发的完整时间线，并在 `issuance_proof` 中证明最终签发依据的是复核通过的确切版本。

意见状态机为 `draft → pending_review → in_review → returned（可回到提交）→ review_passed → issued`。新增权限点 `opinion.read/write/review/issue/dispatch`，其中审计查看员 `auditor` 只读。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。鉴定意见的报告版本只增不改并留存内容摘要、父版本指针和检材/观察记录/方法版本引用，复核任务用条件更新加部分唯一索引保证并发领取只成功一次，历轮已确认章节在退修中不得改写，签发时复核阻断项关闭状态与引用有效性并留存签发版本证据。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
