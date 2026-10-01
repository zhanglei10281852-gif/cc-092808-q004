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
- `app/forensics/opinions.py` 管理鉴定意见不可覆盖版本、签发前复核领取、退修问题与签发依据锚定。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。

## 鉴定意见签发前复核

鉴定意见在签发前必须经过独立复核，全过程留痕且可通过 `GET /api/forensics/opinions/{id}/timeline` 还原：

1. **提交不可覆盖版本**：鉴定人（`opinion.write`）提交报告正文，必须声明所引用的检材、观察记录和实际采用的规程版本；每个版本带 SHA-256 内容哈希，只允许追加新版本，不允许改写或删除。
2. **回避领取**：复核任务先进入待领池，复核人（`opinion.review`）须在 `reviewer_qualifications` 中具备该鉴定专业的有效资质，且不得是意见鉴定人本人；并发领取通过条件更新保证只成功一次。
3. **问题与退修**：复核问题必须包含定位（章节/段落）、严重程度（minor/major/blocking）和处理结论；复核不通过形成退修，鉴定人先提交新版本再逐条回应，复核人可确认关闭或驳回重改，已复核通过的旧版本与问题记录原样保留。
4. **逾期改派**：超过期限未完成的任务可由质量负责人（`opinion.admin`）重新分派（可指定人或回到待领池），原任务标记为 `expired_reassigned`，原领取人、改派人和原因均保留在责任链中，不被抹去。
5. **签发**：质量负责人（`opinion.issue`）签发时，系统确认所有 blocking 问题已关闭、复核通过版本内容哈希未被篡改、所引检验仍为 completed 且观察记录仍归属该检验；签发记录锚定复核通过的确切 `version_id` 和哈希，时间线以 `issuance_proof` 证明两者一致。

角色职责分离：`technician` 起草与退修、`curator` 领取复核、`quality_officer` 登记复核人、改派逾期任务与签发。
