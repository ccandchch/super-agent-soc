# SOC 告警聚合系统 — 部署与对接指南

---

## 一、部署目录结构

只需要以下目录和文件：

```
super-agent-soc/
├── backend/
│   ├── app/
│   │   ├── aggregation/          # ★ 聚合微服务
│   │   │   ├── __init__.py
│   │   │   ├── app.py            # FastAPI 应用 (端口 8004)
│   │   │   ├── models.py         # Event 模型
│   │   │   ├── poller.py         # SIEM 轮询器
│   │   │   ├── event_store.py    # 事件队列
│   │   │   └── routers/
│   │   │       └── consumption.py # Agent 消费 API
│   │   ├── ingestion/            # ★ 告警接入层（webhook 模式）
│   │   │   ├── models.py         # RawAlert, NormalizedAlert
│   │   │   ├── normalizer.py     # 标准化引擎
│   │   │   ├── dedup.py          # 去重聚合引擎
│   │   │   ├── field_mapping.py  # 字段映射配置
│   │   │   ├── app.py            # FastAPI 子应用
│   │   │   ├── queue.py          # 优先级队列
│   │   │   ├── dispatcher.py     # 调度分发器
│   │   │   ├── adapters/         # 适配器
│   │   │   └── routers/          # Webhook 路由
│   │   └── gateway/              # DeerFlow Gateway（已有）
│   └── packages/
│       ├── harness/               # DeerFlow harness（已有）
│       └── memory-soc/            # ★ SOC 记忆服务（可选）
├── docker/
│   └── docker-compose-dev.yaml    # Docker Compose（含 aggregation 服务）
├── scripts/
│   ├── test-alert.sh              # 测试脚本
│   └── mock_siem.py               # Mock SIEM（开发测试用）
├── frontend/src/
│   ├── app/workspace/soc/         # SOC 前端页面
│   ├── components/soc/            # SOC 组件
│   └── core/soc/                  # SOC 业务逻辑 hooks
├── config.yaml                    # DeerFlow 配置
└── extensions_config.json         # MCP 扩展配置
```

不依赖的目录：`mcp-servers/`、`skills/`、`docs/` 仅用于开发参考。

---

## 二、对接 SIEM — 需要修改的接口

### 方式一：轮询模式（聚合微服务，推荐）

**聚合服务通过 HTTP GET 轮询 SIEM 告警查询接口。**

需要 SIEM 提供以下 API：

```
GET {SIEM_API_BASE}/api/v1/alerts?page={N}&size={M}&status=unacknowledged&since={ISO8601}
```

**请求参数：**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `page` | int | 是 | 页码，从 0 开始 |
| `size` | int | 是 | 每页条数（默认 100） |
| `status` | string | 是 | 固定 `unacknowledged`，只拉未确认告警 |
| `since` | string | 否 | ISO8601 时间戳，只拉此时间之后的告警 |

**响应格式：**

```json
{
  "items": [
    {
      "id": "splunk-abc-12345",
      "created_at": "2026-05-12T10:00:01Z",
      "defense_line": "endpoint",
      "name": "Endpoint_Abnormal_Process_Outbound",
      "raw_evidence": {
        "src_ip": "10.23.45.67",
        "dst_ip": "192.168.1.100",
        "process_name": "powershell.exe",
        "process_hash": "abc123def456",
        "hostname": "prod-db-01"
      }
    }
  ],
  "total": 150
}
```

**字段映射规则（`poller.py:100-108`）：**

| SIEM 返回字段 | 映射到 RawAlert 字段 | 说明 |
|-------------|---------------------|------|
| `id` 或 `alarm_id` | `alarm_id` | 告警唯一 ID |
| `created_at` 或 `alert_time` | `alert_time` | 告警时间 |
| `defense_line` | `defense_line` | 六大防线之一 |
| `name` 或 `alert_name` | `alert_name` | 告警名称 |
| `raw_evidence` 或 `evidence` | `raw_evidence` | 原始证据 JSON |

**如果 SIEM 接口格式不同，只需修改 `poller.py:80-108` 的 `_fetch_alerts()` 方法中的字段映射。**

### 方式二：Webhook 推送模式（ingestion 微服务，保留）

SIEM 主动推送告警，无需轮询。接口：

```
POST /api/soc/webhooks/{vendor}
Content-Type: application/json

{
  "alarm_id": "splunk-abc-12345",
  "alert_time": "2026-05-12T10:00:01Z",
  "defense_line": "endpoint",
  "alert_name": "Endpoint_Abnormal_Process_Outbound",
  "raw_evidence": { ... }
}
```

### 告警字段规范

**`defense_line` 六选一：** `endpoint` | `server` | `application` | `network` | `email` | `account`

**`alert_name` 示例：**
```
Endpoint_Abnormal_Process_Outbound → 类型映射为 malware
Email_Phishing_Link_Click          → 类型映射为 phishing
Network_C2_Communication           → 类型映射为 network_c2
```

类型映射表在 `ingestion/normalizer.py:17-27`，新增告警名称需同步添加。

---

## 三、配置环境变量

### 聚合微服务

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SIEM_API_BASE` | `http://siem:8080` | SIEM 平台 API 地址 |
| `SIEM_API_KEY` | 空 | SIEM API 认证 key（可选） |
| `SOC_POLL_INTERVAL` | `60` | 轮询间隔（秒） |
| `SOC_POLL_PAGE_SIZE` | `100` | 分页大小 |
| `AGGREGATION_PORT` | `8004` | 聚合服务端口 |

### Ingestion 微服务

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SOC_FLUSH_INTERVAL` | `30` | Webhook 缓冲窗口（秒），0 为同步模式 |
| `SOC_LANGGRAPH_URL` | `http://localhost:8001/api` | LangGraph API 地址 |

### Docker Compose

在 `docker-compose-dev.yaml` 的 `aggregation` 服务中配置：

```yaml
environment:
  - SIEM_API_BASE=${SIEM_API_BASE:-http://your-siem:8080}
  - SIEM_API_KEY=${SIEM_API_KEY:-}
  - SOC_POLL_INTERVAL=${SOC_POLL_INTERVAL:-60}
```

启动前设置：
```bash
export SIEM_API_BASE=http://10.0.0.50:8080
export SIEM_API_KEY=your-api-key
make docker-start
```

---

## 四、使用方式

### 本地开发（不含 Docker）

```bash
# 终端 1：启动 mock SIEM（开发测试）
python3 scripts/mock_siem.py 9090

# 终端 2：启动聚合服务
cd backend && \
  SIEM_API_BASE=http://localhost:9090 \
  SOC_POLL_INTERVAL=10 \
  PYTHONPATH=. uv run uvicorn app.aggregation.app:app --port 8004 --reload

# 终端 3：模拟 Agent 消费事件
curl http://localhost:8004/api/aggregation/events/next    # 拿 1 条
curl http://localhost:8004/api/aggregation/events/status  # 查看状态
curl http://localhost:8004/api/aggregation/events/peek    # 查看全部（不消费）
```

### Docker 部署

```bash
# 配置 SIEM 地址
export SIEM_API_BASE=http://your-siem:8080

# 启动全服务
make docker-start

# 查看聚合服务日志
tail -f logs/aggregation.log

# 查看 Gateway 日志
tail -f logs/gateway.log
```

### 发送测试告警

```bash
# 本地（需先登录获取 session）
bash scripts/test-alert.sh

# 或直接 curl
curl -X POST http://localhost:2026/api/soc/webhooks/siem_splunk \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" -b "access_token=$ACCESS; csrf_token=$CSRF" \
  -d '{"alarm_id":"test-001","alert_time":"2026-05-14T10:00:00Z","defense_line":"endpoint","alert_name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.0.0.1","process_hash":"abc123"}}'
```

### 前端访问

```
http://localhost:2026/workspace/soc/alerts       # 告警工作台
http://localhost:2026/workspace/soc/dashboard    # 运营仪表盘
http://localhost:2026/workspace/soc/rules        # 抑制规则
http://localhost:2026/workspace/soc/audit        # 审计日志
```

---

## 五、聚合参数调优

| 参数 | 位置 | 默认值 | 说明 |
|------|------|--------|------|
| 实体重叠阈值 | `ingestion/dedup.py:86` | 0.55 | Jaccard 相似度，低于此值不聚合 |
| 聚合时间窗口 | `ingestion/dedup.py:87` | 300s | 两条告警时间差超过此窗口不聚合 |
| 单次聚合上限 | `ingestion/dedup.py:88` | 10 条 | 超过则拆分为新分组 |
| 轮询间隔 | 环境变量 `SOC_POLL_INTERVAL` | 60s | SIEM 拉取频率 |
| 缓冲窗口 | 环境变量 `SOC_FLUSH_INTERVAL` | 30s | Webhook 模式缓冲时间 |

---

## 六、Agent 消费接口

Agent 通过 HTTP 从聚合服务拉取事件：

```
GET http://localhost:8004/api/aggregation/events/next
```

**成功响应（200）：**
```json
{
  "id": "uuid",
  "defense_line": "endpoint",
  "alert_name": "Endpoint_Abnormal_Process_Outbound",
  "alert_type": "malware",
  "severity": "high",
  "source_alarms": [
    {"alarm_id": "siem-001", "alert_name": "Endpoint_Abnormal_Process_Outbound", "alert_time": "2026-05-12T10:00:01Z"},
    {"alarm_id": "siem-002", "alert_name": "Endpoint_Abnormal_Process_Outbound", "alert_time": "2026-05-12T10:00:15Z"},
    {"alarm_id": "siem-003", "alert_name": "Endpoint_Abnormal_Process_Outbound", "alert_time": "2026-05-12T10:00:30Z"}
  ],
  "entity_overlap": 0.71,
  "occurrence_count": 3,
  "entities": [
    {"type": "ip", "value": "10.23.45.1"},
    {"type": "hash", "value": "abc123def456"}
  ],
  "raw_evidence": {
    "common": { "process_hash": "abc123def456", "hostname": "prod-db-01" },
    "per_alarm": {
      "siem-001": { "src_ip": "10.23.45.1" },
      "siem-002": { "src_ip": "10.23.45.2" }
    }
  },
  "created_at": "2026-05-12T10:00:30Z",
  "consumed": true
}
```

**空队列（204）：** 无响应体

Agent 消费流程：
1. `GET /events/next` → 拿到一条 Event → 自动标记 `consumed=true`
2. Agent 根据 `raw_evidence` 执行研判
3. `GET /events/next` → 下一条（或 204 表示暂时没有）
