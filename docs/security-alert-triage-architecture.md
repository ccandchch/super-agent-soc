# AI Agent 安全告警自动化研判系统 — 架构设计

---

## 一、系统定位与核心设计原则

本系统在安全运营体系中的定位：**告警消费侧的智能调度与增强层**，处在 SIEM/EDR/NDR 等检测系统与安全分析师之间。它不替代检测规则，也不取代人的判断；它负责压缩机械劳动、聚合上下文、引导注意力分配，让分析师从"翻日志找证据"变成"审简报做裁决"。

六条设计原则贯穿全部层级：

1. **分析只跑一次，呈现按需渲染** — 研判管线是公共资产，不同角色看到的是同一结果对象的不同视图。
2. **MCP 标准化工具接入** — 所有外部数据源（情报、CMDB、身份、SIEM）通过 MCP Server 解耦，Agent 只依赖协议不依赖实现。
3. **Skill 封装研判套路** — 每类告警的研判链路是可版本化、可替换、可回滚的独立模块。
4. **Subagent 并发与隔离** — 单条告警的 Subagent 故障不影响其他告警，资源配额兜底。
5. **人裁决、系统学习、但系统不自动生效变更** — 模式发现是自动的，策略变更必须经人审批。
6. **架构服从业务场景** — 白天/凌晨、分析师/运维/新人，不是建三条流水线，而是一套管线加消费端渲染路由。

---

## 二、二开总体策略

基于 [DeerFlow](https://github.com/ByteDance/deer-flow) 进行二开，各层复用/自建决策：

| 层级 | 策略 | 说明 |
|------|------|------|
| 告警消费与路由层 | **同仓库新增 FastAPI 微服务** | 独立端口 8002，与 Gateway 共存但逻辑隔离 |
| Agent 编排层 | **复用 DeerFlow + 核心扩展** | 新增 `deerflow/triage/` 模块，纵向切入 middlewares/subagents/tools；不改已有核心逻辑 |
| 研判分析层 | **复用 DeerFlow** | 以 Skill + MCP Tool 形式承载研判逻辑，Agent 自主决策加载哪个 Skill |
| 上下文提供层 | **MCP + 社区工具混合** | 多工具数据源走 MCP Server（独立进程），简单单次查询走社区工具（进程内） |
| 输出与交互层 | **单一前端 + 路由隔离** | DeerFlow Next.js 前端新增 `/soc/*` 路由，共享组件库/认证/API 层 |
| 记忆与学习层 | **完全自建** | DeerFlow 记忆系统面向对话助手，SOC 需要告警级/资产级/模式级记忆，业务逻辑完全不匹配 |
| 运营度量层 | **自建 + 集成到同一前端** | `/soc/dashboard` 路由，采集系统+研判+业务三层指标 |

---

## 三、告警数据模型

### 3.1 输入模型（上游推送）

上游系统通过 webhook 推送告警，字段固定：

```json
{
  "alarm_id":      "splunk-abc-12345",
  "alert_time":    "2026-05-10T14:32:00Z",
  "defense_line":  "endpoint",
  "alert_name":    "Endpoint_Abnormal_Process_Outbound",
  "raw_evidence": {
    "src_ip":        "10.23.45.67",
    "dst_ip":        "192.168.1.100",
    "process_name":  "powershell.exe",
    "process_hash":  "abc123def456",
    "process_path":  "C:\\Windows\\Temp\\evil.ps1",
    "parent_process": "winword.exe"
  }
}
```

### 3.2 六条防线

| 防线 | 枚举值 | 典型告警 |
|------|--------|---------|
| 终端 | `endpoint` | Endpoint_Abnormal_Process_Outbound, Endpoint_Ransomware_Detected |
| 服务器 | `server` | Server_Privilege_Escalation, Server_Webshell_Upload |
| 应用 | `application` | App_SQL_Injection, App_XSS_Attack |
| 网络 | `network` | Network_C2_Communication, Network_Port_Scan |
| 邮件 | `email` | Email_Phishing_Link_Click, Email_Malicious_Attachment |
| 账号 | `account` | Account_Brute_Force, Account_Impossible_Travel |

### 3.3 标准化输出模型 (NormalizedAlert)

```json
{
  "id": "uuid-v7",
  "source": "siem_splunk",
  "defense_line": "endpoint",
  "alert_name": "Endpoint_Abnormal_Process_Outbound",
  "type": "malware",
  "severity": "critical",
  "entities": [
    {"type": "ip",   "value": "10.23.45.67"},
    {"type": "ip",   "value": "192.168.1.100"},
    {"type": "hash", "value": "abc123def456"},
    {"type": "process", "value": "powershell.exe"}
  ],
  "fingerprint": "sha256(entities排序后拼接)",
  "rule_id": "Endpoint_Abnormal_Process_Outbound",
  "alarm_id": "splunk-abc-12345",
  "deduped_alarm_ids": ["splunk-abc-12346", "splunk-abc-12347"],
  "raw_evidence": {
    "src_ip": "10.23.45.67",
    "dst_ip": "192.168.1.100",
    "process_name": "powershell.exe",
    "process_hash": "abc123def456",
    "process_path": "C:\\Windows\\Temp\\evil.ps1",
    "parent_process": "winword.exe"
  },
  "created_at": "2026-05-10T14:32:00Z"
}
```

> `alarm_id` 为上游 SIEM 的原始告警 ID，前端查看完整 payload 时通过此 ID 调用 SIEM 查询接口获取。`deduped_alarm_ids` 为指纹去重时被移除的重复告警 ID 列表，研判完成后结果通过各 ID 回传给对应 SIEM。`raw_evidence` 携带完整原始载荷供 Agent 研判时读取，落库时仅存引用不存全文。

### 3.4 聚合告警 (AggregatedAlert)

同防线内，两条或以上告警满足以下条件时合并为一条，避免同一事件被重复研判：

- 实体重叠度 > 75%（可配置）
- 时间差 < 5 分钟（可配置）
- 防线相同，告警名称可以不同
- 单次聚合上限 10 条（可配置），超出则拆分为多个聚合组
- 聚合后严重级别取各告警中的最高值

```json
{
  "id": "uuid-v7",
  "type": "malware",
  "defense_line": "endpoint",
  "severity": "critical",
  "entities": [
    {"type": "hash", "value": "abc123def456"},
    {"type": "ip", "value": "10.23.45.100"},
    {"type": "ip", "value": "192.168.1.200"},
    {"type": "host", "value": "prod-db-01"}
  ],
  "fingerprint": "merged:a1b2c3d4e5f67890",
  "alarm_id": null,
  "aggregation": {
    "entity_overlap": 0.85,
    "time_delta_seconds": 42,
    "source_alarms": [
      {
        "alarm_id": "splunk-abc-12345",
        "alert_name": "Endpoint_Abnormal_Process_Outbound"
      },
      {
        "alarm_id": "splunk-abc-12346",
        "alert_name": "Endpoint_Malicious_Network_Connection"
      }
    ]
  },
  "raw_evidence": {
    "common": {
      "process_hash": "abc123def456",
      "host": "prod-db-01"
    },
    "per_alarm": {
      "splunk-abc-12345": {
        "src_ip": "10.23.45.67",
        "dst_ip": "192.168.1.100",
        "alert_details": "检测到异常进程外联行为"
      },
      "splunk-abc-12346": {
        "src_ip": "10.23.45.67",
        "dst_ip": "8.8.8.8",
        "alert_details": "检测到进程注入后向外部 C2 地址发起连接"
      }
    }
  },
  "created_at": "2026-05-10T14:32:00Z"
}
```

> `raw_evidence.common` — 所有告警中字段值相同的部分，确认指向同一事件；`raw_evidence.per_alarm` — 各告警中值不同的字段按 alarm_id 分别存放，Agent 一次研判即可覆盖全貌。聚合时不提升严重级别，仅合并上下文。

---

## 四、代码组织与模块划分

```
super-agent-soc/
├── backend/
│   ├── app/
│   │   ├── gateway/              # [现有] DeerFlow Gateway (端口 8001)
│   │   └── ingestion/            # [新增] 告警消费微服务 (端口 8002)
│   │       ├── __init__.py
│   │       ├── app.py            # FastAPI 子应用
│   │       ├── adapters/
│   │       │   ├── __init__.py
│   │       │   ├── base.py       # 适配器抽象接口
│   │       │   └── siem_webhook.py  # SIEM webhook 接收器
│   │       ├── normalizer.py     # 标准化引擎
│   │       ├── dedup.py          # 去重与聚合器
│   │       ├── queue.py          # 优先级队列（五因子排序）
│   │       ├── dispatcher.py     # 队列消费 → 调用 DeerFlow API 创建 Thread/Run
│   │       └── routers/
│   │           ├── __init__.py
│   │           ├── webhooks.py   # POST /api/soc/webhooks/{vendor}
│   │           └── queue_status.py  # GET /api/soc/queue/status
│   │
│   └── packages/
│       ├── harness/deerflow/
│       │   └── triage/           # [新增] SOC Agent 编排模块
│       │       ├── __init__.py
│       │       ├── middleware.py    # 告警上下文注入中间件
│       │       ├── scheduler.py    # 调度器 Master Agent
│       │       ├── scorer.py       # 置信度评分器
│       │       ├── attack_chain.py # 攻击链关联器
│       │       ├── state.py        # 告警研判状态扩展
│       │       └── subagents/      # SOC 专用 Subagent 类型
│       │
│       ├── harness/deerflow/community/cmdb/  # [新增] CMDB 社区工具
│       │   ├── __init__.py
│       │   └── tools.py           # query_asset 工具
│       │
│       └── memory-soc/           # [新增] SOC 记忆服务（独立包）
│           ├── pyproject.toml
│           └── soc_memory/
│               ├── __init__.py
│               ├── api.py            # 内部 API（相似度查询、结果 CRUD）
│               ├── session_store.py  # Redis 会话状态
│               ├── result_store.py   # PostgreSQL 研判结果
│               ├── feedback.py       # 反馈采集与存储
│               ├── clustering.py     # 定时聚类引擎
│               ├── suppression.py    # 抑制规则管理
│               ├── pattern_store.py  # 攻击链模式库
│               └── models.py         # SQLAlchemy/SQLModel 模型
│
├── mcp-servers/                  # [新增] SOC MCP Server 实现
│   ├── threat-intel/
│   │   ├── pyproject.toml
│   │   └── server.py             # 多源情报聚合（MCP SSE Server）
│   ├── siem-search/
│   │   ├── pyproject.toml
│   │   └── server.py             # SIEM 日志检索
│   └── sandbox/
│       ├── pyproject.toml
│       └── server.py             # 沙箱分析
│
├── skills/public/                # [新增] SOC Skill
│   ├── malware-triage/           # 恶意软件研判 Skill
│   ├── phishing-triage/          # 钓鱼邮件研判 Skill
│   ├── anomaly-login-triage/     # 异常登录研判 Skill
│   └── data-exfil-triage/        # 数据泄露研判 Skill
│
├── frontend/src/
│   ├── app/(workspace)/soc/      # [新增] SOC 路由
│   │   ├── layout.tsx            # SOC 布局（导航+面包屑）
│   │   ├── alerts/page.tsx       # 告警工作台
│   │   ├── triage/[thread_id]/page.tsx  # 研判详情
│   │   ├── dashboard/page.tsx    # 运营仪表盘
│   │   ├── rules/page.tsx        # 抑制规则管理
│   │   └── audit/page.tsx        # 审计日志查询
│   ├── core/soc/                 # [新增] SOC 业务逻辑
│   │   ├── alerts.ts             # 告警列表 API hooks
│   │   ├── queue.ts              # 队列状态 hooks
│   │   ├── triage.ts             # 研判结果 hooks
│   │   └── feedback.ts           # 反馈提交 hooks
│   └── components/soc/           # [新增] SOC 组件
│       ├── alert-card.tsx        # 告警卡片
│       ├── alert-filter.tsx      # 筛选面板
│       ├── alert-summary.tsx     # 告警摘要条
│       ├── triage-result.tsx     # 研判结果面板
│       └── queue-stats.tsx       # 队列统计数字
│
├── config.yaml                   # [修改] 新增 soc 段 + cmdb 社区工具
└── extensions_config.json        # [修改] 新增 threat-intel/siem-search/sandbox MCP Server
```

---

## 五、告警消费与路由层（Ingestion 微服务）

### 5.1 告警接入方式

告警进入系统有两种方式，适配器需同时支持：

**方式一 — Webhook 推送（Push）**：SIEM 平台运行 SPL 模型产生告警时，在模型内部执行算子，将告警内容通过 HTTP POST 推送到 Ingestion 服务。

```
SIEM SPL模型 → 算子 → POST /api/soc/webhooks/{vendor} → Adapter → RawAlert
```

**方式二 — API 主动拉取（Pull）**：Ingestion 服务定时轮询 SIEM 平台的告警查询接口，拉取新产生的告警。

```
Ingestion定时任务 → GET /siem/api/alerts?since={timestamp} → Adapter → RawAlert
```

两种方式可并存，按 vendor 配置选择。适配器职责纯粹：协议转换 + 格式映射，不包含业务逻辑。

### 5.2 标准化引擎 (normalizer.py)

输入 `RawAlert`，输出 `NormalizedAlert`：

```
RawAlert → 防线枚举校验 → 告警名称→type 映射 → 实体提取 → 严重级别归一化 → 指纹生成 → NormalizedAlert
```

**告警名称到类型映射表**（初期静态维护，后续可运营校准）：

```
Endpoint_Abnormal_Process_Outbound → malware
Endpoint_Ransomware_Detected       → ransomware
Email_Phishing_Link_Click          → phishing
Email_Malicious_Attachment         → malware
Network_C2_Communication           → network_c2
Network_Port_Scan                  → recon
Account_Brute_Force                → anomaly_login
Account_Impossible_Travel          → anomaly_login
Server_Privilege_Escalation        → privilege_escalation
...
```

**实体提取**：raw_evidence 中的字段名有两类，需分别处理：

1. **语义化字段**（如 `src_ip`、`process_hash`）→ 按字段名模式自动识别：

```
*_ip / *_ip_src / *_ip_dst   → entity.type = "ip"
*_hash / *_md5 / *_sha256     → entity.type = "hash"
*_domain / *_url              → entity.type = "domain" / "url"
*_user* / *_account*          → entity.type = "user"
*_host* / *_hostname*         → entity.type = "host"
*_process*                    → entity.type = "process"
```

2. **通用字段**（如 `key_word1`、`key_word2`、`field_1`）→ 通过每条告警名称的字段映射配置提取，维护一份 `alert_name → field_mapping` 配置表：

```yaml
# 示例：告警字段映射配置
Endpoint_Abnormal_Process_Outbound:
  fields:
    key_word1: { entity_type: "process", entity_key: "process_name" }
    key_word2: { entity_type: "ip" }
    key_word3: { entity_type: "hash" }
    field_1:   { entity_type: "host" }
```

> 两种方式互为补充：语义化字段自动识别覆盖面广，字段映射配置覆盖通用字段名场景。新增告警名称时需同步配置映射表。

**指纹生成**：entities 数组按 `(type, value)` 确定性排序 → 拼接为规范字符串 → SHA256 → 取前 16 字符作为 fingerprint。

### 5.3 去重与聚合器 (dedup.py)

分两步处理：

**第一步 — 指纹去重**：以 `fingerprint` 为键，在可配置时间窗口内（默认 10 分钟）去重。同指纹再次出现时，不创建新的研判任务，但将该 `alarm_id` 追加到首个告警的 `deduped_alarm_ids` 列表中。研判完成后，结果通过各 alarm_id 回传给对应 SIEM。

**第二步 — 实体聚合**：对通过去重的告警做同防线内聚合，条件：
- 实体重叠度 > 75%（可配置）
- 时间差 < 5 分钟（可配置）
- 单次聚合上限 10 条（可配置），超出则拆分为多个聚合组
- 聚合后严重级别取各告警中的最高值

聚合后产出一条 `AggregatedAlert`，`raw_evidence` 按 common + per_alarm 组织（见 3.4），送入优先级队列。未满足聚合条件的告警直接以 NormalizedAlert 形态入队列。

### 5.4 优先级队列 (queue.py)

五个优先级槽位，排序因子（权重可配置）：

| 因子 | 权重 | 说明 |
|------|------|------|
| 告警自身严重级别 | 0.40 | critical > high > medium > low |
| 涉及资产的业务关键性 | 0.30 | 由 CMDB 查询结果提供 |
| 同资产窗口期内告警密度 | 0.20 | 密度越高优先级越高 |
| Agent 历史判定不确定度 | 0.10 | 首次 0.10，后续根据历史偏差更新 |

API：`dequeue(consumer_role)`, `peek_top(n)`, `reprioritize(alert_id)`。

### 5.5 调度分发器 (dispatcher.py)

告警消费的最后一环，职责简洁 —— 从队列拉取告警，调用 DeerFlow API：

```
Queue.dequeue()
    │
    ▼
查询历史相似告警 (memory-soc API)
    │
    ├─ 精确匹配 + 历史高置信(≥0.95)恶意 + 72小时内
    │   → 快速研判：复用结论，仅更新告警时间+递增频次计数+写入审计日志
    │
    ├─ 精确匹配 + 历史低置信/误报
    │   → 创建 Thread/Run，注入历史上下文到首条消息
    │
    ├─ 高相似（同防线+同告警名+实体重叠>75%）
    │   → 创建 Thread/Run，注入同类告警统计到首条消息
    │
    └─ 无匹配
        → 正常创建 Thread/Run，首条消息=告警 JSON
```

```
POST /api/langgraph/threads
    → thread_id
POST /api/langgraph/threads/{thread_id}/runs
    {
      "input": {
        "messages": [{
          "role": "user",
          "content": "<alert>告警JSON + 历史上下文(如有)</alert>"
        }]
      },
      "config": {
        "recursion_limit": 100,
        "configurable": {
          "model_name": "claude-opus-4-7",
          "thinking_enabled": true
        }
      }
    }
```

---

## 六、Agent 编排与研判分析层

本层通过新建 `deerflow/triage/` 模块实现，纵向切入 DeerFlow harness 的 middlewares、subagents、tools 层。不修改已有核心逻辑，利用 DeerFlow 扩展点注册 SOC 专用组件。

### 6.1 Skill 驱动的研判模型

每条告警（或聚合后的告警）是独立的 Thread。流程：

```
Dispatcher 创建 Thread/Run
       │
       ▼
Agent 收到系统提示词中的 Skill 列表（SKILL.md 头部元数据注入）
       │
       ▼
Agent 根据告警内容自主判断是否匹配某个 Skill
       │
       ├─ 匹配：调用 read_file("skills/public/malware-triage/SKILL.md") 加载完整 Skill
       │    → 按 Skill 步骤执行研判
       │    → 调用 MCP/社区工具收集上下文
       │    → 输出结构化结论
       │
       └─ 不匹配：Agent 通用推理 → 输出结论
```

### 6.2 Skill 扩展

每个 SOC Skill 是一个目录，包含 `SKILL.md`（YAML frontmatter + 研判剧本）：

```
skills/public/malware-triage/
├── SKILL.md           # 研判剧本（步骤、分支、结论模板、评分因子）
└── references/        # 参考资料（可选）
```

`SKILL.md` frontmatter 示例：

```yaml
---
name: malware-triage
description: 恶意软件告警研判 — 适用于 endpoint/server 防线的恶意软件/勒索/Webshell 类告警。包含威胁情报哈希查询、进程链追溯、沙箱分析三个标准步骤，最终输出恶意确认/误报/不确定三维结论。
allowed-tools:
  - query_hash
  - query_ip
  - query_domain
  - search_events
  - get_report
  - query_asset
  - read_file
  - bash
---
```

Agent 按 DeerFlow 的 Progressive Loading Pattern 工作：先看到系统提示词里的 Skill 元数据 → 判定匹配 → 调用 `read_file` 加载完整剧本 → 按步骤执行。

### 6.3 SOC 专用工具接入

详见第七章的 MCP + 社区工具混合方案。Agent 在研判过程中按 Skill 步骤调用这些工具收集上下文。

### 6.4 置信度评分器 (scorer.py)

在 Agent 完成 Skill 步骤后，收集证据栈，输出三维度分数：

```json
{
  "verdict": "malicious",
  "confidence": 0.87,
  "confidence_level": "medium",
  "severity": "high",
  "factors": {
    "threat_intel_match": { "score": 0.95, "weight": 0.4 },
    "process_chain_anomaly": { "score": 0.80, "weight": 0.2 },
    "sandbox_confirmed":   { "score": 0.90, "weight": 0.3 },
    "org_prevalence_low":  { "score": 0.70, "weight": 0.1 }
  },
  "uncertainties": [
    "沙箱分析结果为 7 天前，当前文件版本可能不同"
  ]
}
```

置信度区间：`≥0.95` → high, `0.70-0.94` → medium, `<0.70` → low。

### 6.5 攻击链关联器 (attack_chain.py)

独立后台组件，维护攻击链模式库（基于 MITRE ATT&CK）。持续扫描已完成研判的告警，按 `entity_key` 做时序对齐。当匹配某模式超过 `min_matched_stages` 时，打包为 `CompositeIncident`，升级严重级别。

---

## 七、上下文提供层（MCP + 社区工具混合）

### 7.1 选型决策

| 能力 | 接入方式 | 理由 |
|------|---------|------|
| **threat-intel** | MCP Server (SSE) | 多工具（query_ip/hash/domain/url），一个 Server 自然聚合多情报源，独立部署方便升级 |
| **siem-search** | MCP Server (SSE) | 多工具（search_events/get_alert_context），查询逻辑复杂，独立进程利于限流和隔离 |
| **sandbox** | MCP Server (SSE) | 多工具（get_report/submit_file），submit 是异步任务，MCP 工具天然支持长耗时 |
| **cmdb** | 社区工具（进程内） | `query_asset` 是简单 HTTP 封装，不值得起独立进程；一个 `@tool` 函数 + `config.yaml` 一行配置即可 |

### 7.2 MCP Server 注册

在 `extensions_config.json` 中：

```json
{
  "mcpServers": {
    "threat-intel": {
      "enabled": true,
      "type": "sse",
      "url": "http://localhost:8101/sse",
      "headers": { "Authorization": "Bearer $TI_API_TOKEN" },
      "description": "多源威胁情报聚合：query_ip, query_hash, query_domain, query_url"
    },
    "siem-search": {
      "enabled": true,
      "type": "sse",
      "url": "http://localhost:8102/sse",
      "headers": { "Authorization": "Bearer $SIEM_API_TOKEN" },
      "description": "SIEM 日志检索：search_events, get_alert_context"
    },
    "sandbox": {
      "enabled": true,
      "type": "sse",
      "url": "http://localhost:8103/sse",
      "description": "沙箱分析：get_report, submit_file"
    }
  }
}
```

### 7.3 CMDB 社区工具注册

在 `config.yaml` 中：

```yaml
tools:
  - name: query_asset
    group: soc
    use: deerflow.community.cmdb.tools:query_asset_tool
    api_base_url: $CMDB_API_URL
    api_key: $CMDB_API_KEY
```

### 7.4 MCP Server 实现

每个 MCP Server 是独立 Python 包，位于 `mcp-servers/` 目录下，使用 `mcp` 库实现 SSE Server。本地开发时用 mock server 返回固定数据即可。

**threat-intel 工具定义：**

```
query_ip(ip: str) → { verdict, confidence, sources[], tags[], last_seen, geo }
query_hash(hash: str) → { verdict, confidence, sources[], family, tags[], first_seen }
query_domain(domain: str) → { verdict, confidence, sources[], category, registrar }
query_url(url: str) → { verdict, confidence, sources[], category, scan_results }
```

内部聚合多源（VT / 微步 / AlienVault / AbuseIPDB），统一返回 `verdict: malicious | suspicious | clean | unknown`。

**siem-search 工具定义：**

```
search_events(entity: str, entity_type: str, time_window: str) → { events[], total_count }
get_alert_context(alert_id: str) → { alert_detail, related_events[], same_host_alerts_24h, same_user_alerts_24h }
```

**sandbox 工具定义：**

```
get_report(hash: str) → { report_id, hash, verdict, behavioral_summary, network_connections[], created_at }
submit_file(file_path: str) → { report_id, status: "queued | running | completed" }
```

### 7.5 降级策略

当某个 MCP Server 不可用时：

```
threat-intel 不可用 → 置信度锁定 medium，附加 uncertainty "威胁情报查询不可用"
siem-search 不可用  → 跳过日志检索步骤，置信度扣减 0.1
sandbox 不可用      → 跳过沙箱步骤，置信度扣减 0.15
cmdb 不可用         → 使用缓存（标记过期），置信度扣减 0.1
```

降级后的研判决不触发自动处置，必须走人工审核。

---

## 八、输出与交互层（前端）

### 8.1 路由设计

在 DeerFlow Next.js 前端中新增 `/soc/*` 路由组，共享组件库、认证和 API 层，通过 Nginx 路由分发：

```
/soc/alerts              → 告警工作台（队列视图、筛选、卡片列表）
/soc/triage/[thread_id]  → 研判详情（复用 DeerFlow Chat 组件 + 研判结果面板）
/soc/dashboard           → 运营仪表盘
/soc/rules               → 抑制规则管理
/soc/audit               → 审计日志查询
```

### 8.2 告警工作台 `/soc/alerts`

- **左侧筛选面板**：防线（6 类联动告警名称）、严重级别、时间范围、研判状态
- **实时统计数字**：队列积压量、处理中数量（轮询 `/api/soc/queue/status`）
- **告警卡片列表**：按优先级排列，每张卡片显示严重级别色标 + 防线 + 告警名称 + 关键实体 + 时间 + 优先级分数
- 点击卡片 → 跳转 `/soc/triage/{thread_id}`

### 8.3 研判详情 `/soc/triage/[thread_id]`

- **顶部**：固定告警摘要条（防线、告警名称、关键实体、时间），不作为对话内容
- **左侧**：复用 DeerFlow 聊天界面，渲染 Agent 研判对话流（Skill 加载 → 工具调用 → 证据收集 → 结论输出）
- **右侧面板**：结构化研判结果 → 判定结论、置信度、严重级别、证据链列表、建议操作
- **底部操作栏**：采纳 / 否决 / 升级（注入历史上下文选项）—— 对应消费状态机

### 8.4 消费状态机

同一研判结果可能被不同消费者先后处理：

```
未消费 → 已推送 → 已查看 → 采纳 → 已处置（闭环）
                          → 否决 → 已重新分配 → (回到已推送)
                          → 升级 → 已重新分配 → (回到已推送给高级分析师)
```

### 8.5 导航集成

在 DeerFlow 左侧导航栏新增 SOC 入口，面包屑导航 `Workspace > SOC > 告警工作台`。

---

## 九、记忆与学习层（memory-soc）

与 DeerFlow 记忆系统（面向对话助手的用户级 JSON 文件存储）完全独立，SOC 记忆面向告警级/资产级/模式级的数据管理。

### 9.1 存储选型

| 数据类型 | 存储 | 理由 |
|---------|------|------|
| 会话状态 | Redis KV | 高并发读写、心跳续期、TTL 过期 |
| 研判结果 | PostgreSQL | 结构化查询、JSONB 字段、关联分析 |
| 反馈记录 | PostgreSQL | 关联结果表、分析查询 |
| 抑制规则 | PostgreSQL | CRUD 简单、审批状态流转 |
| 攻击链模式 | PostgreSQL | 运营手动维护、低频变更 |

### 9.2 会话状态存储 (Redis)

```
Key: triage:task:{task_id}
Value: {
  task_id, alert_id, thread_id,
  status: queued | running | completed | timeout | error,
  started_at, last_heartbeat,
  tool_calls_count, tool_calls_remaining,
  current_step, result_ref,
  consumer_states: [{ user, role, action, at }]
}
TTL: 24小时（完成后保留）
```

### 9.3 研判结果存储 (PostgreSQL)

```sql
triage_results:
  result_id          UUID PRIMARY KEY
  alert_id           UUID NOT NULL
  thread_id          TEXT NOT NULL
  defense_line       TEXT
  alert_name         TEXT
  verdict            TEXT     -- malicious | false_positive | benign_anomaly | uncertain
  confidence         FLOAT
  confidence_level   TEXT     -- high | medium | low
  severity           TEXT
  summary            TEXT
  evidence_timeline  JSONB    -- [{ step, name, tool, finding, evidence_ref }]
  action_suggestion  JSONB    -- { primary, params, rationale }
  uncertainties      JSONB    -- [string]
  skill_version      TEXT
  degraded           BOOLEAN
  created_at         TIMESTAMP
```

### 9.4 反馈记录 (PostgreSQL)

```sql
feedback:
  id             UUID PRIMARY KEY
  result_id      UUID FK → triage_results
  analyst        TEXT
  action         TEXT     -- accepted | rejected | escalated
  reject_reason  TEXT     -- evidence_insufficient | logic_error | threshold_conservative | other
  comment        TEXT
  created_at     TIMESTAMP
```

### 9.5 相似告警查询

Dispatcher 在创建 Run 前查询历史，接口：

```
GET /api/soc/memory/similar-alerts
  ?fingerprint={fp}
  &defense_line={line}
  &alert_name={name}
  &entities={json_array}
  &lookback_days=30

Response:
{
  exact_match: {              // 同指纹精确匹配，存在则非 null
    result_id, verdict, confidence, created_at, occurrence_count
  },
  similar_alerts: [{          // 实体重叠 > 50%
    result_id, verdict, confidence, entity_overlap, created_at
  }],
  same_type_stats: {          // 同类告警统计
    total, malicious, false_positive, uncertain
  }
}
```

快速研判阈值（`config.yaml` 可配）：

```yaml
soc:
  fast_triage:
    enabled: true
    exact_match:
      confidence_threshold: 0.95
      max_age_hours: 72
    similar_match:
      entity_overlap_threshold: 0.75
      lookback_days: 30
```

### 9.6 反馈聚类引擎

每日凌晨定时任务：

1. 拉取过去 7 天反馈记录
2. 按 `(skill_id, step_id, verdict)` 聚类否决案例
3. 否决率 > 20%（可配置）的聚类 → 生成分析报告 + 推送运营负责人
4. 运营负责人选择"批准修改 Skill"或"忽略"

引擎只做发现和建议，**不自动修改任何 Skill 或规则**。修改走 Skill 版本管理 + 审批流程。

### 9.7 抑制规则管理

当同一 `(rule_id, entity_pattern)` 组合被分析师连续 N 次推翻后，生成抑制规则草案 → 推送审批 → 生效。命中规则的告警自动降低优先级或标记为 suppress。有效期可配置（7 天/30 天/永久），到期自动失效并通知复核。

---

## 十、运营度量层

### 10.1 三层指标体系

**系统健康指标（SRE 视角）：**

| 指标 | 告警阈值 |
|------|---------|
| `alert_ingestion_rate` | — |
| `queue_depth` | > 500 |
| `analysis_latency_p95` | > 120s |
| `agent_timeout_rate` | > 5% |
| `mcp_availability` | < 99% |

**研判质量指标（安全运营视角）：**

| 指标 | 目标 |
|------|------|
| `auto_accuracy`（分析师采纳率） | ≥ 90% |
| `false_negative_rate`（Agent 判误实为真） | < 0.1% |
| `analyst_time_saved` | 持续改善 |

**业务价值指标（管理层视角）：**

| 指标 | 说明 |
|------|------|
| `mttd_delta` | Agent 辅助前后平均检测时间对比 |
| `mttr_delta` | Agent 辅助前后平均处置时间对比 |
| `alert_fatigue_score` | 分析师手动关闭频率趋势（下降代表疲劳改善） |

### 10.2 审计日志

所有关键操作写入不可变审计日志：

- 告警的进入、排队、派发、完成
- 每个 Subagent 的工具调用（工具名、参数哈希、结果摘要、耗时）
- 自动处置操作
- 分析师的操作（采纳、否决、升级、备注）
- Skill 版本切换、抑制规则变更

日志保留：在线 90 天（Elasticsearch/ClickHouse），归档 1 年。

---

## 十一、总体数据流

```
1. SIEM 产生告警
       │
       ▼
2. POST /api/soc/webhooks/splunk
       │
       ▼
3. Adapter → Normalizer → Dedup → PriorityQueue
       │
       ▼
4. Dispatcher.dequeue()
       ├─ 查询 memory-soc 历史相似告警
       │    ├─ 高置信精确匹配 → 快速研判，跳过 5-6
       │    └─ 否 → 继续
       │
       ▼
5. POST /api/langgraph/threads → thread_id
   POST /api/langgraph/threads/{id}/runs
       │
       ▼
6. Agent 自主决策加载 Skill → 执行研判步骤
       ├─ 调用 MCP/社区工具收集上下文
       ├─ Scorer 评分
       └─ 输出结构化结论 → 写入 memory-soc
       │
       ▼
7. 视图路由器 → 分析师简报卡 / 应急引导卡 / 培训学习卡
       │
       ▼
8. 分析师采纳/否决/升级 → 反馈记录 → 聚类引擎 → 运营决策建议
```

---

## 十二、部署视图

```
                    ┌─────────────┐
                    │   Nginx     │
                    │  port 2026  │
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           │               │               │
    /api/soc/*      /api/*           /*
           │               │               │
     ┌─────▼─────┐  ┌──────▼──────┐  ┌─────▼──────┐
     │ Ingestion │  │   Gateway   │  │  Frontend  │
     │  :8002    │  │   :8001     │  │   :3000    │
     └──┬───┬────┘  └──┬──┬──┬───┘  └────────────┘
        │   │          │  │  │
        │   │  ┌───────┘  │  └──────────────────┐
        │   │  │          │                     │
        │   │  │  ┌───────▼──────────┐          │
        │   │  │  │  LangGraph       │          │
        │   │  │  │  Runtime (内置)   │          │
        │   │  │  │  + MCP Client    │          │
        │   │  │  └──┬──┬──┬────────┘          │
        │   │  │     │  │  │                    │
   ┌────▼───▼──▼─┐   │  │  │                    │
   │ memory-soc  │   │  │  │                    │
   │ (内部 API    │   │  │  │                    │
   │  localhost   │   │  │  │                    │
   │  :8003)      │   │  │  │                    │
   └──┬────┬─────┘   │  │  │                    │
      │    │          │  │  │                    │
 ┌────▼┐ ┌─▼──┐  ┌────▼──▼──▼────┐               │
 │Redis│ │ PG │  │  MCP Servers  │               │
 └─────┘ └────┘  │ threat-intel  │               │
                 │  :8101        │               │
                 │ siem-search   │               │
                 │  :8102        │               │
                 │ sandbox       │               │
                 │  :8103        │               │
                 └───────────────┘               │
                                                 │
   ┌─────────────────────────────────────────────┘
   │  CMDB 作为社区工具运行在 Gateway 进程内
   │  (deerflow.community.cmdb)
```

- Ingestion (8002) 与 Gateway (8001) 独立端口，便于独立扩缩容和限流
- LangGraph Runtime 内嵌在 Gateway 中，MCP Client (`MultiServerMCPClient`) 由 DeerFlow 进程内管理，直连各 MCP Server
- CMDB 作为社区工具运行在 Gateway 进程内，不走独立进程
- memory-soc (8003) 仅监听 localhost，不经过 Nginx 对外暴露
- MCP Server 可部署在同一主机或独立主机，通过 HTTP/SSE 通信
- 前端通过 Nginx 反向代理统一访问

---

## 十三、关键设计决策记录

| 决策 | 原因 |
|------|------|
| Ingestion 独立端口 (8002) | 告警接入流量特征（突发、webhook）与用户交互 API 不同 |
| 告警消费层不做 Skill 匹配 | Skill 由 Agent 按系统提示词自主判断加载，遵循 DeerFlow Progressive Loading 模式 |
| 每条告警独立 Thread | 与 DeerFlow 对话模型一致，天然支持隔离和状态管理 |
| 威胁情报/沙箱/SIEM 走 MCP | 多工具聚合 + 独立部署 + 标准化协议，遵循架构原则 |
| CMDB 走社区工具 | 简单单次查询，不值得起独立进程 |
| memory-soc 完全自建 | DeerFlow 记忆系统面向对话场景，与 SOC 业务逻辑完全不匹配 |
| 相似度查询放在 Dispatcher | 在创建 Run 前做快速判断，避免重复研判浪费 LLM 调用 |
| 聚类引擎只建议不自动修改 | 安全策略变更需要上下文理解，属于运营决策不适合自动 |
| 前端路由隔离 | 共享 DeerFlow 基础设施，但页面和状态管理独立 |
