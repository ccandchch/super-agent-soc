# SOC 告警聚合服务

独立微服务，轮询 SIEM 平台获取告警，自动聚合为事件，提供 API 供 AI Agent 消费。

## 目录结构

```
aggregation-service/
├── pyproject.toml          # Python 依赖
├── .env.example            # 环境变量模板
├── README.md               # 本文件
└── app/
    ├── __init__.py
    ├── aggregation/         # 聚合服务主模块
    │   ├── __init__.py
    │   ├── app.py           # FastAPI 入口 (端口 8004)
    │   ├── models.py        # Event 事件模型
    │   ├── poller.py        # SIEM 轮询 + 聚合
    │   ├── event_store.py   # 线程安全事件队列
    │   └── routers/
    │       └── consumption.py  # Agent 消费 API
    └── ingestion/           # 告警标准化模块
        ├── models.py        # RawAlert, NormalizedAlert
        ├── normalizer.py    # 标准化引擎
        ├── field_mapping.py # 字段映射配置
        └── dedup.py         # 去重聚合引擎
```

## 快速启动

```bash
cp .env.example .env
# 编辑 .env，填写 SIEM_API_BASE

uv sync
source .env
uv run uvicorn app.aggregation.app:app --host 0.0.0.0 --port 8004
```

## API

### Agent 消费事件

```
GET /api/aggregation/events/next    → 200 + Event JSON，自动标记 consumed
                                    → 204 队列空
GET /api/aggregation/events/status  → {"total": N, "unconsumed": M}
GET /api/aggregation/events/peek    → [Event, ...]  不消费，仅查看
```

### Event 字段

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID | 事件唯一 ID |
| defense_line | string | 防线 |
| alert_name | string | 告警名称 |
| alert_type | string | 统一类型（malware, phishing...） |
| severity | string | 聚合组内最高级别 |
| source_alarms | array | 所有源告警 ID |
| entity_overlap | float | Jaccard 重叠度 |
| occurrence_count | int | 聚合告警数 |
| entities | array | 合并后的实体 |
| raw_evidence.common | dict | 所有告警相同字段 |
| raw_evidence.per_alarm | dict | 各告警独有字段（按 alarm_id） |
| consumed | bool | 是否已消费 |

## 对接 SIEM

### SIEM 需实现接口

```
GET {SIEM_API_BASE}/api/v1/alerts?page={N}&size={M}&status=unacknowledged&since={ISO8601}
```

**请求参数：**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| page | int | 是 | 页码，从 0 开始 |
| size | int | 是 | 每页条数 |
| status | string | 是 | 固定 `unacknowledged` |
| since | string | 否 | ISO8601，增量拉取 |

**响应格式：**
```json
{
  "items": [
    {
      "id": "唯一告警ID",
      "created_at": "2026-05-12T10:00:01Z",
      "defense_line": "endpoint",
      "name": "Endpoint_Abnormal_Process_Outbound",
      "raw_evidence": {
        "src_ip": "10.23.45.67",
        "dst_ip": "192.168.1.100",
        "process_hash": "abc123def456",
        "hostname": "prod-db-01"
      }
    }
  ],
  "total": 150
}
```

### 自定义适配

修改 `app/aggregation/poller.py` 第 100-108 行的字段映射：

```python
RawAlert(
    alarm_id=item.get("id", ...),           # SIEM 告警 ID 字段名
    alert_time=item.get("created_at", ...), # 时间字段名
    defense_line=item.get("defense_line", "endpoint"),
    alert_name=item.get("name", ...),       # 告警名称字段名
    raw_evidence=item.get("raw_evidence", item.get("evidence", {})),
)
```

### 告警字段规范

**defense_line（必填）：** `endpoint` | `server` | `application` | `network` | `email` | `account`

**新增告警名称：** 在 `app/ingestion/normalizer.py` 的 `ALERT_TYPE_MAP` 添加类型映射。

**通用字段名：** 在 `app/ingestion/field_mapping.py` 配置 `key_word1` 等字段的实体类型。

## 聚合逻辑

1. **轮询** → 每 N 秒分页拉取 SIEM 未确认告警
2. **指纹去重** → 同实体指纹窗口内丢弃
3. **实体聚合** → Jaccard ≥ 0.55 + 时间差 < 5min → 合并
4. **跨轮次** → 分组保留 5min，新告警继续合并
5. **取代** → 新事件覆盖旧事件重叠的 alarm_id
6. **消费** → Agent 逐条拉取

## 参数调优

| 参数 | 位置 | 默认值 |
|------|------|--------|
| 重叠阈值 | `app/ingestion/dedup.py:86` | 0.55 |
| 时间窗口 | `app/ingestion/dedup.py:87` | 300s |
| 单次上限 | `app/ingestion/dedup.py:88` | 10 |
| 轮询间隔 | `.env` `SOC_POLL_INTERVAL` | 60s |
| 分页大小 | `.env` `SOC_POLL_PAGE_SIZE` | 100 |

## FAQ

### Jaccard 重叠度如何计算

不是比较两条告警的实体，而是比较**新告警 vs 整个分组累计实体集**：

```
                     | 新告警实体 ∩ 分组累计实体 |
Jaccard = ——————————————————————————————————
                     | 新告警实体 ∪ 分组累计实体 |
```

**分组累计实体集**（`group.entity_set`）随着每条告警加入而膨胀。示例：

```
分组初始（siem-001 加入后）：
  entity_set = {ip:10.23.45.1, ip:192.168.1.100, hash:abc123, process:powershell, host:prod-db-01}
  共 5 个

siem-002 比较：
  新告警 = {ip:10.23.45.2, ip:192.168.1.100, hash:abc123, process:powershell, host:prod-db-01}
  交集 = 4, 并集 = 6
  Jaccard = 4/6 = 0.667 ≥ 0.55 → 合并
  分组 entity_set 增长为 6 个

siem-003 同样合并，分组 entity_set 增长为 7 个

siem-004 比较：
  新告警有 5 个实体，分组累计有 7 个
  交集 = 4, 并集 = 5 + 7 - 4 = 8
  Jaccard = 4/8 = 0.50 < 0.55 → 不合并，开新分组
```

**不同 src_ip 越多，分组累计实体集越大，Jaccard 越低。** 阈值太低会导致无关告警误合并，太高会导致相关告警漏合并，需要根据实际告警数据调优。

### 单事件最大告警数

`max_aggregation_size = 10`（`app/ingestion/dedup.py:88`），可配置。

达到上限后，该分组跳过新告警（`dedup.py:186-187`），新告警匹配时**新建一个分组**。已满的分组不会被删除，在 5 分钟超时后自动清理。

**实际效果：** 1 分钟内涌入 30 条相同模式的告警 → 生成 3 个 Event（各 10 条）。

### raw_evidence 字段值支持列表吗

支持。三种格式自动识别：

| 格式 | 示例 | 处理 |
|------|------|------|
| 单字符串 | `"src_ip": "10.0.0.1"` | 提取 1 个实体 |
| 字符串列表 | `"src_ip": ["10.0.0.1", "10.0.0.2"]` | 展开为 2 个实体 |
| 混合 | `"key_word1": ["10.0.0.1", "10.0.0.2"]` | 同上 |

### 在哪里配置 field_mapping

`app/ingestion/field_mapping.py`（仅 SIEM 使用 `key_word1`、`field_1` 等通用字段名时需要）。

```python
FIELD_MAPPING = {
    "告警名称": {
        "fields": {
            "SIEM字段名": {"entity_type": "实体类型"},                    # 简单映射
            "SIEM字段名": {"entity_type": "实体类型", "entity_key": "子字段"},  # 嵌套取值
        }
    },
}

# 示例
FIELD_MAPPING = {
    "Endpoint_Abnormal_Process_Outbound": {
        "fields": {
            "key_word1": {"entity_type": "process"},
            "key_word2": {"entity_type": "ip"},
            "key_word3": {"entity_type": "hash"},
            "field_1":  {"entity_type": "host"},
        }
    },
    "Network_C2_Communication": {
        "fields": {
            "detail": {"entity_type": "ip", "entity_key": "src_ip"},
        }
    },
}
```

语义化字段名（`src_ip`、`process_hash`、`hostname` 等）由正则自动识别，不需要配置。

### 告警名称类型映射在哪里

`app/ingestion/normalizer.py` 的 `ALERT_TYPE_MAP`：

```python
ALERT_TYPE_MAP = {
    "Endpoint_Abnormal_Process_Outbound": "malware",
    "Email_Phishing_Link_Click": "phishing",
    # 新增告警名称在此添加
}
```

## Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install uv && uv sync
EXPOSE 8004
CMD ["uv", "run", "uvicorn", "app.aggregation.app:app", "--host", "0.0.0.0", "--port", "8004"]
```
