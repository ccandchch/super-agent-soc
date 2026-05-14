# SOC 告警研判系统 — 待办事项

> 2026-05-10，ingestion pipeline 实施完成后梳理

---

## 一、当前可运行状态

**已实现（14 commits，3072 tests pass）：**

| 模块 | 状态 |
|------|------|
| Ingestion 微服务（webhook → 标准化 → 去重 → 队列） | ✅ 已实现，Docker 中已验证 |
| SOC 前端页面（告警工作台、研判详情、预留页面） | ✅ 已实现，可访问 |
| Memory-SOC 模型 + API | ✅ 代码已写，Docker 中未启动 |
| CMDB 社区工具 | ✅ 已注册 |
| MCP Server 骨架（3个 mock） | ✅ 已创建 |

**启动方式：**
```bash
make docker-start    # Docker 全服务
# 访问: http://localhost:2026/workspace/soc/alerts
```

---

## 二、待修复（阻塞）

### 1. Dispatcher 后台循环未启动

**现象：** 告警已成功入队（webhook 返回 202，队列 depth=1），但 Dispatcher 的 `dispatch_loop` 从未执行。Gateway 启动日志中没有 `"Dispatcher loop started"`，没有任何 Thread/Run 创建请求。

**原因：** `app.mount("/api/soc", soc_ingestion)` 挂载的子应用 lifespan 在 Docker 中未正确触发。

**修复方向：** 将 Dispatcher 启动逻辑移到主 Gateway 的 lifespan 中，而非依赖子应用 lifespan。

### 2. Docker 网络下 Dispatcher URL 错误

即使 Dispatcher 启动，默认 `langgraph_url="http://localhost:2026/api/langgraph"` 在 Docker 容器内不可达（nginx 在独立容器）。应改为 `http://localhost:8001/api` 或通过环境变量配置。

---

## 三、待实现（Agent 编排层 — 用户自行处理）

1. **Agent 编排层** — 新建 `deerflow/triage/` 模块（scheduler、scorer、attack_chain、middleware、subagents）
2. **SOC Skill 编写** — malware-triage、phishing-triage、anomaly-login-triage、data-exfil-triage 的 SKILL.md
3. **Run 结果消费** — 研判完成后将 TriageResult 写回 memory-soc（`POST /api/results`）
4. **系统提示词修改** — 注入 SOC Skill 元数据，让 Agent 自主判断加载哪个 Skill

---

## 四、待完善

| 事项 | 说明 |
|------|------|
| Triage 详情页动态数据 | `AlertSummary` 当前硬编码，需从 API 获取告警元数据 |
| Memory-SOC 启动 | 需手动 `uvicorn soc_memory.app:app --port 8003`，无 Docker Compose 配置 |
| MCP Server 启动 | 三个 mock server 需分别手动启动（端口 8101-8103） |
| 前端 SOC 导航入口 | 在 DeerFlow 左侧导航栏添加 SOC 链接 |
| 运营仪表盘 | 当前 placeholder，需实现三层指标体系 |
| 抑制规则管理 | 当前 placeholder，需实现 CRUD + 审批流 |
| 审计日志 | 当前 placeholder，需实现全生命周期审计追踪 |

---

## 五、快速验证命令

```bash
# 注册 + 登录获取 token
curl -s -X POST http://localhost:2026/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@soc-triage.com","password":"S0cTr1age!2026","name":"Admin"}'

RESP=$(curl -s -D - -X POST http://localhost:2026/api/v1/auth/login/local \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=admin@soc-triage.com&password=S0cTr1age!2026')
CSRF=$(echo "$RESP" | grep -o 'csrf_token=[^;]*' | cut -d= -f2)
ACCESS=$(echo "$RESP" | grep -o 'access_token=[^;]*' | cut -d= -f2)

# 发测试告警
curl -s -X POST http://localhost:2026/api/soc/webhooks/siem_splunk \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -b "access_token=$ACCESS; csrf_token=$CSRF" \
  -d '{"alarm_id":"test-001","alert_time":"2026-05-10T14:32:00Z","defense_line":"endpoint","alert_name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.45.67","process_hash":"abc123"}}'

# 查看队列
curl -s http://localhost:2026/api/soc/queue/status \
  -H "X-CSRF-Token: $CSRF" \
  -b "access_token=$ACCESS; csrf_token=$CSRF"
```
