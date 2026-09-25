# 网络前缀策略分析 API（Network Prefix Policy Analyzer）

基于 **Python 3.12 + FastAPI + SQLite** 的服务：提交一组带 **优先级、动作、来源标签** 的
IPv4/IPv6 CIDR 规则，服务端按 **最长前缀匹配（LPM）+ 同前缀优先级裁决** 计算每条规则的
**实际覆盖范围**，识别：

- **完全遮蔽（fully shadowed）**：规则的整个 CIDR 被更长前缀全部拿走，实际不转发任何地址；
- **部分重叠（partial overlap）**：部分范围被更长前缀覆盖（给出碎片 CIDR 列表）；
- **动作冲突（action conflict）**：重叠且动作不同（permit vs deny），并给出**可复现的最小冲突对**
  及其精确的 `override_range`；
- **优先级反转（priority inversion）**：长前缀仅凭前缀长度（而非更高优先级数字）覆盖短前缀
  且改变动作时给出提示。

分析结果是**确定性**的：相同输入得到相同 `ruleset_hash` 与版本 `id`。支持保存分析版本、
按条件查询规则/发现、导出 JSON，并通过一个带乐观锁（`revision`）的**发布指针**在已保存
版本之间安全切换，切换历史只增可查。相同规则集的重复保存（包括并发提交）是**幂等**的：
只保留首次保存的版本与元数据，见下文[“重复提交语义（幂等）”](#重复提交语义幂等)。

---

## 一条命令启动（Docker Compose）

```bash
docker compose up --build -d
```

- 服务监听端口：**8080**（宿主机与容器内一致）
- API 根地址：<http://localhost:8080/>
- 交互式文档（Swagger UI）：<http://localhost:8080/docs>
- 健康检查：<http://localhost:8080/health>

SQLite 数据文件保存在命名卷 `prefix_data`（容器内 `/data/prefix_policy.db`），容器重启后
已保存的分析版本不丢失。停止：`docker compose down`（加 `-v` 同时删除数据卷）。

### 不用 Docker，直接本地运行

需要 Python 3.11+：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

数据库默认落在 `/data/prefix_policy.db`；该目录不可写时自动回退到系统临时目录
`$TMPDIR/prefix_policy.db`。可用环境变量 `PREFIX_DB_PATH` 显式指定：

```bash
PREFIX_DB_PATH=./data/policy.db uvicorn app.main:app --host 0.0.0.0 --port 8080
```

运行测试：

```bash
python -m pytest -q
```

---

## 规则与裁决语义

| 字段 | 说明 |
| --- | --- |
| `cidr` | IPv4/IPv6 CIDR，如 `10.0.0.0/8`、`2001:db8::/32`；**主机位必须为 0**（`10.0.0.5/24` 会被拒绝） |
| `action` | `permit`（别名 `allow`/`accept`/`pass`）或 `deny`（别名 `block`/`drop`/`reject`），大小写不敏感 |
| `priority` | 整数，**数值越小优先级越高**，默认 `100`。仅用于裁决**完全相同 CIDR** 的规则 |
| `source_tag` | 来源标签（自由文本），默认 `default`，如 `hq` / `edge-fw` / `terraform` |
| `rule_id` | 可选唯一 ID；不填则自动生成 `r1, r2, ...` |

转发模型采用经典最长前缀匹配：

1. **更长前缀永远胜出**——即使它的 `priority` 数字更"低"（数值更大）。此时若动作也发生变化，
   该边会被标记 `priority_inversion: true`。
2. **同一 CIDR 的多条规则**归并为一个 trie 节点：优先级最高（数字最小，再按提交顺序）者为
   **winner**，其余为 **duplicate**，实际覆盖为 0（`role: "duplicate"`, `status: "shadowed"`）。
3. 规则 R 的**实际覆盖** = `cidr(R)` − 其所有 winner 子节点 CIDR 的并集，以 CIDR 碎片列表
   `effective_cidrs` 返回：
   - 碎片为空 → `status: "shadowed"`（完全遮蔽）
   - 有碎片且存在子节点 → `status: "partial"`（部分重叠）
   - 无子节点 → `status: "active"`

### 最小冲突对（minimal_conflict_pairs）

对每个**实际转发至少一个地址**的节点 N（`effective_cidrs` 非空），沿祖先链向上查找：
**跳过动作与 N 相同的祖先**，与第一个动作不同的祖先配对。该对的 `override_range` 精确等于
N 的实际覆盖碎片。

跳过同动作祖先保证了结果**最小且无遗漏**——例如 `permit /8 → deny /16 → deny /17 ×2`，
/16 被两个 deny 的 /17 完全遮蔽时，内部没有冲突，但两个 /17 会"穿过"同动作的 /16 与 /8
配对，而死规则 /16 自身不产生对。输出按规则 ID 排序，完全可复现。

---

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/analyze` | 分析规则集（默认保存；`save:false` 只算不存） |
| POST | `/api/analyses/{id}/simulate` | 基于已保存版本预演 add/replace/remove 规则变更（**不落库**），返回新分析结果与语义差异 |
| POST | `/api/analyses/{id}/merge-precheck` | **双批次变更合并预检**：A、B 两组 add/replace/remove 基于同一基线分别重算，检测结构冲突/地址动作冲突/合并冲突（**不落库**），无冲突时返回合并分析与相对基线差异 |
| POST | `/api/analyses/{id}/quarantine-plan` | **临时封禁方案预演**：给定严格目标 CIDR 与新规则 ID 前缀，确定性生成 `priority=0` 的 deny 新增规则清单，使目标内全部转为 deny、目标外动作不变（**不落库**） |
| POST | `/api/analyses/{id}/traffic-audit` | **访问观测归因**：把一批观测到的访问记录（IP + 实际动作 + 可选次数）按 LPM + 同前缀优先级归因到胜出规则，逐条核对一致性并加权汇总（**不落库**） |
| POST | `/api/analyses/{id}/observation-correction` | **观测纠偏**：给定 1～20 条 IP + 期望动作与 1～8 个互异、存在的候选 rule_id，枚举 keep/disable/flip 组合，返回改动规则数最少（并列时停用数最少、再按序列字典序）的纠偏方案（**不落库**） |
| GET | `/api/analyses` | 列出已保存版本（`limit`/`offset` 分页） |
| GET | `/api/analyses/{id}` | 取某个版本的完整分析结果 |
| GET | `/api/analyses/{id}/rules` | 查询规则：`status=active/partial/shadowed`、`action=permit/deny`、`ip=4/6` |
| GET | `/api/analyses/{id}/findings` | 查询发现：`severity=conflict/warning/info`、`behavioral_only=true` |
| GET | `/api/analyses/{id}/decision-map?cidr=...` | 只读的 **CIDR 决策地图**：把查询网段切成最小 CIDR 分块，给出最终动作/胜出规则/完整匹配链 |
| GET | `/api/analyses/{id}/redundant-rules` | **冗余规则盘点**：逐条移除规则并重算 LPM 裁决，标记可安全删除的规则（**不落库**） |
| GET | `/api/analyses/{id}/source-retirement` | **来源撤场预演**：对每个 `source_tag` 一次性整组移除其全部规则并重算 LPM，给出可否整组撤场与按动作转变归类的最小 CIDR（**不落库**） |
| GET | `/api/analyses/{id}/export.json` | 以附件形式导出完整结果 JSON |
| GET | `/api/analyses/{base}/diff/{target}` | 两个已保存版本的**最终生效动作语义差异**（最小 CIDR + 分类计数） |
| POST | `/api/analyses/{base}/change-guard/{target}` | **变更守卫**：用调用方给出的授权条目核对两版本的语义差异，返回是否通过及未授权的最小 CIDR |
| GET | `/api/active` | 查看**发布指针**：当前发布的已保存版本 `active_id` 与乐观锁 `revision`（初始 `null` / `0`） |
| POST | `/api/active/activate` | **发布/切换**已保存版本：提交 `analysis_id` 与 `expected_revision`，同一事务内核对并递增 `revision`；冲突返回 `409` 及当前状态 |
| GET | `/api/active/history` | **只读**发布历史：每次成功切换的前后版本、时间与 revision（`limit`/`offset` 分页） |
| GET | `/health` | 健康检查 |

### 示例：提交分析

```bash
curl -s -X POST http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "dc-2026-09",
    "rules": [
      {"cidr": "10.0.0.0/8",   "action": "permit", "priority": 100, "source_tag": "hq"},
      {"cidr": "10.10.0.0/16", "action": "deny",   "priority": 500, "source_tag": "dc1"},
      {"cidr": "10.10.1.0/24", "action": "permit", "priority": 900, "source_tag": "lab"},
      {"cidr": "2001:db8::/32", "action": "deny",  "source_tag": "v6"}
    ]
  }'
```

响应（节选）：

```json
{
  "id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "persisted": true,
  "summary": {
    "rule_count": 4, "distinct_cidrs": 4,
    "active_rules": 2, "partial_rules": 2, "shadowed_rules": 0,
    "behavioral_conflicts": 2, "priority_inversions": 2
  },
  "rules": [
    {
      "rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit",
      "priority": 100, "source_tag": "hq",
      "role": "winner", "status": "partial",
      "covered": 16711680, "total_addresses": 16777216,
      "effective_cidrs": ["10.0.0.0/13", "10.8.0.0/15", "..."],
      "covered_by": ["r2"], "has_conflict": true
    }
  ],
  "findings": [
    {
      "type": "cover", "severity": "conflict",
      "rule_id": "r2", "other_rule_id": "r1",
      "cidr": "10.10.0.0/16", "parent_cidr": "10.0.0.0/8",
      "child_action": "deny", "parent_action": "permit",
      "action_conflict": true, "behavioral": true,
      "priority_inversion": true,
      "reason": "rule 'r2' (deny) overrides 'r1' (permit) on 10.10.0.0/16 via longer prefix"
    }
  ],
  "minimal_conflict_pairs": [
    {
      "kind": "cover", "rule_id": "r2", "other_rule_id": "r1",
      "action": "deny", "other_action": "permit", "winner_rule_id": "r2",
      "cidr": "10.10.0.0/16",
      "override_range": ["10.10.0.0/24", "10.10.2.0/23", "..."],
      "reason": "longest-prefix match: 'r2' (deny) wins over 'r1' (permit) on this range"
    }
  ]
}
```

### 重复提交语义（幂等）

`POST /api/analyze` 默认 `save: true`。版本以规则集内容的 `ruleset_hash` 去重：

- **首次保存**：创建一个不可变版本（`analyses` 一行，外加该版本的 rules / findings
  记录），响应的 `id` 为 `an_` + 哈希前 16 位，`name` 为请求携带的 `name`，
  `created_at` 为首次保存时刻。
- **重复提交**（相同规则集再次提交，无论是否携带不同的 `name`）：**不会**创建新版本，
  数据库中仍然只有一份 analyses/rules/findings；响应直接返回**首次保存版本**的
  `id`、`name`、`created_at`——重复请求自带的 `name` 被忽略，`persisted` 仍为 `true`。
  该响应与 `GET /api/analyses/{id}` 及 `GET /api/analyses` 版本列表中的元数据完全一致。
- **并发重复提交**：多个携带相同规则集的保存请求同时到达时，去重在单个 SQLite
  写事务内原子完成（配合 `ruleset_hash` 唯一索引）：恰好一个请求完成插入，其余请求
  全部复用同一已保存版本，所有成功响应拿到**同一个 `id`**，只产生一份
  analyses/rules/findings，不会返回服务错误。
- `save: false` 时只做分析、不写库：每次都返回按请求参数生成的响应（`id` 仍由哈希
  确定性推导、`name` 取请求值、`created_at` 为本次时间），`persisted: false`，数据库
  中不产生任何记录。

### 查询与导出

```bash
# 只看部分重叠的规则
curl -s "http://localhost:8080/api/analyses/an_e38b58f57faf2325/rules?status=partial"

# 只看真正改变转发行为的冲突发现
curl -s "http://localhost:8080/api/analyses/an_e38b58f57faf2325/findings?behavioral_only=true"

# 导出 JSON 文件
curl -sOJ "http://localhost:8080/api/analyses/an_e38b58f57faf2325/export.json"
```

### 规则变更预演（simulate）

在某个**已保存版本**之上预演一批规则变更，无需另存为新版本。服务端从该版本的保存结果
**重建原始分析输入**，按 `rule_id` 定位并应用 `add` / `replace` / `remove` 三类操作，
然后重新执行 LPM 分析，返回：

- `simulated`：补丁后的**完整分析结果**（与 `/api/analyze` 同构），但 `id: null`、
  `persisted: false`——**不会创建任何分析记录**，数据库中不新增 analyses/rules/findings 行；
- `diff`：预演结果相对**基准版本**的最终生效动作语义差异（结构同
  `/api/analyses/{base}/diff/{target}`，`target.id` 为 `null`）。

批次契约（**任一操作非法则整批拒绝**，错误中 `issues` 一次性列出全部问题）：

| 操作 | 请求体 | 定位要求 |
| --- | --- | --- |
| `add` | 完整新规则（`rule_id` 必填） | `rule_id` 必须是基准版本中**不存在的新 ID**；新规则按请求顺序追加在幸存规则之后（顺序仍参与同 CIDR 优先级裁决） |
| `replace` | 完整替换规则（`rule_id` 必填） | `rule_id` 必须**命中基准版本**；整条规则就地替换、保留原位置，不允许改名 |
| `remove` | `{"rule_id": "..."}` | `rule_id` 必须**命中基准版本** |

- 每个 `rule_id` 在整批中**最多成为一个操作的目标**（同一列表重复、跨列表同时出现都拒绝）；
- 补丁后规则集不能为空（不能删光所有规则）；
- 新增/替换规则里的 CIDR、action 仍按既有规则校验，非法时返回与 `/api/analyze` 一致的
  `400 invalid_ruleset`；字段层面错误（未知字段、缺 `rule_id`、未知 action 等）返回 `422`。

删除或改写更具体的子网规则后，**祖先规则会在让出的范围上重新生效**：例如
`permit 10.0.0.0/8 → deny 10.1.0.0/16 → permit 10.1.1.0/24` 中删掉 deny /16 后，
permit /8 祖先重新转发 `10.1.0.0/16 − 10.1.1.0/24`（diff 中表现为一组
`deny_to_permit` 的最小 CIDR），而 permit /24 孙子规则不受影响。

```bash
curl -s -X POST http://localhost:8080/api/analyses/an_e38b58f57faf2325/simulate \
  -H 'Content-Type: application/json' \
  -d '{
    "remove":  [{"rule_id": "r2"}],
    "replace": [
      {"rule_id": "r3", "cidr": "10.10.1.0/24", "action": "deny",
       "priority": 900, "source_tag": "lab"}
    ],
    "add": [
      {"rule_id": "r9", "cidr": "10.20.0.0/16", "action": "deny",
       "priority": 400, "source_tag": "dc2"}
    ]
  }'
```

响应（节选）：

```json
{
  "base": {"id": "an_e38b58f57faf2325", "ruleset_hash": "e38b58f5...", "analyzer_version": "1.0.0"},
  "simulated": {
    "analyzer_version": "1.0.0",
    "ruleset_hash": "7c41...（预演输入的哈希，仅用于本次响应）",
    "id": null,
    "name": null,
    "persisted": false,
    "summary": {"rule_count": 3, "...": "..."},
    "rules": ["...完整规则结果..."],
    "findings": ["..."],
    "minimal_conflict_pairs": ["..."]
  },
  "diff": {
    "base":   {"id": "an_e38b58f57faf2325", "ruleset_hash": "e38b58f5...", "analyzer_version": "1.0.0"},
    "target": {"id": null, "ruleset_hash": "7c41...", "analyzer_version": "1.0.0"},
    "changes": [
      {"ip_version": 4, "change_type": "deny_to_permit",
       "from_action": "deny", "to_action": "permit",
       "address_count": 65280, "range_count": 8,
       "cidrs": ["10.10.0.0/24", "10.10.2.0/23", "..."]},
      {"ip_version": 4, "change_type": "none_to_deny",
       "from_action": null, "to_action": "deny",
       "address_count": 65536, "range_count": 1, "cidrs": ["10.20.0.0/16"]}
    ],
    "summary": {"...": "与版本语义差异相同的分类计数..."}
  }
}
```

非法批次的 `400` 响应（示例：add 撞了已有 ID、remove 指向不存在的 ID）：

```json
{
  "error": "invalid_simulation",
  "detail": "add targets existing rule_id 'r1'; ...; remove targets unknown rule_id 'zz'; ...",
  "issues": [
    "add targets existing rule_id 'r1'; add may only introduce a new rule_id",
    "remove targets unknown rule_id 'zz'; it must match a rule of the base version"
  ]
}
```

基准版本不存在 → `404`。预演不产生任何副作用，可安全重复调用；若补丁与基准完全等价
（如用相同记录 replace），`diff.changes` 为空且 `ruleset_hash` 与基准一致。

### 双批次变更合并预检（merge precheck）

`POST /api/analyses/{id}/merge-precheck` 审查两组**各自独立、都基于同一已保存基线**的
add/replace/remove 变更（请求体里的 `a`、`b`，结构同 simulate 批次）能否一起落地。服务端
**重建基线输入后分别重算两侧的最终生效动作**，全部为纯网段几何运算（IPv4/IPv6 各自独立、
不枚举地址），**不新建分析版本、不写库、不修改基线**。按顺序给出四类结论：

1. **结构冲突 `structural_conflicts`**：同一 `rule_id` 同时成为 A、B 两批操作的目标
   （两侧都 remove 也算）——两边都要在同一条基线上决定这条规则的命运，无法直接合并；
   每条冲突给出 `rule_id` 与 `side_a_operation` / `side_b_operation`。
2. **地址动作冲突 `action_conflicts`**：取**两侧各自相对基线发生动作改变的地址范围**，
   按 IPv4/IPv6 精确叠加；在两侧都改过、但**最终动作不同**的交集上产生冲突，输出
   **最小 CIDR**（相邻同前缀兄弟块会合并）及 `base_action`（基线动作，无规则命中为 `null`）、
   `side_a_action`、`side_b_action` 与精确地址数。两侧改成**相同动作**的交集不算冲突；
   只有一侧改变的范围也不算。
3. **合并冲突 `merge_conflicts`**：在没有前两类冲突时，**先应用 A、再在 A 的结果上应用 B**
   （A 的 add 排在 B 的 add 之前，同 CIDR 裁决据此定序），对合并规则集**重新执行 LPM 分析**；
   然后逐地址核对两侧相对基线改变过的范围——若合并结果在某侧改过的范围上**没有保持该侧的
   最终动作**，就产生冲突，给出 `side`（`"a"`/`"b"`）、`base_action`、该侧 `side_action`、
   `merged_action` 与最小 CIDR。它能发现直接叠加看不出来的交互：例如基线是
   `deny /8 → permit /16`，A 把 /16 改成 deny（/16 permit→deny），B 在其中加一条
   permit /24（相对基线是 no-op，基线 /16 本就 permit）——直接叠加两侧改变范围无交集，
   但 A 后 B 的合并结果里更长的 permit /24 胜出，把 A 在 /24 上的 deny 改回了 permit。
4. **全部通过**：`passed: true`，返回 `merged`（合并后的**完整分析结果**，`id: null`、
   `persisted: false`）与 `diff`（合并结果相对**基线**的最终生效动作语义差异，结构同
   版本语义差异端点）。

存在结构冲突或地址动作冲突时，依赖该阶段的后续结果置为 `null`（`merged`/`diff`/
`merge_conflicts`）。批次契约与 simulate 完全一致——每批至少一个操作、每批独立相对基线
校验（add 必须是基线中不存在的新 ID，replace/remove 必须命中基线，每个目标每批最多一次，
单批不能删光规则）。两批**合起来**删光所有规则是合法合并（合并结果所有地址为 `none`，
照常返回差异）。

```bash
curl -s -X POST http://localhost:8080/api/analyses/an_e38b58f57faf2325/merge-precheck \
  -H 'Content-Type: application/json' \
  -d '{
    "a": {
      "add": [{"rule_id": "a9", "cidr": "10.20.0.0/16", "action": "deny"}]
    },
    "b": {
      "remove": [{"rule_id": "r2"}],
      "add": [{"rule_id": "b9", "cidr": "10.30.0.0/16", "action": "permit"}]
    }
  }'
```

无冲突响应（节选）：

```json
{
  "base": {"id": "an_e38b58f57faf2325", "ruleset_hash": "e38b58f5...", "analyzer_version": "1.0.0"},
  "sides": {
    "a": {"ruleset_hash": "1f2a...", "rule_count": 5},
    "b": {"ruleset_hash": "9d7c...", "rule_count": 5}
  },
  "passed": true,
  "structural_conflicts": [],
  "action_conflicts": [],
  "merge_conflicts": [],
  "merged": {
    "analyzer_version": "1.0.0",
    "ruleset_hash": "c11e...（合并输入的哈希，仅用于本次响应）",
    "id": null, "name": null, "persisted": false,
    "summary": {"rule_count": 5, "...": "..."},
    "rules": ["...完整规则结果..."],
    "findings": ["..."],
    "minimal_conflict_pairs": ["..."]
  },
  "diff": {
    "base":   {"id": "an_e38b58f57faf2325", "ruleset_hash": "e38b58f5...", "analyzer_version": "1.0.0"},
    "target": {"id": null, "ruleset_hash": "c11e...", "analyzer_version": "1.0.0"},
    "changes": ["...合并结果相对基线的最小 CIDR 动作差异..."],
    "summary": {"...": "与版本语义差异相同的分类计数..."}
  },
  "summary": {
    "structural_conflicts": 0,
    "action_conflict_ranges": 0,
    "action_conflict_addresses": 0,
    "merge_conflict_ranges": 0,
    "merge_conflict_addresses": 0
  }
}
```

地址动作冲突示例响应（基线 `permit 10.0.0.0/8`；A 删掉该规则、B 加 `deny 10.1.0.0/16`，
交集 /16 上 A 为 `null`(none)、B 为 deny）：

```json
{
  "passed": false,
  "structural_conflicts": [],
  "action_conflicts": [
    {
      "ip_version": 4,
      "base_action": "permit",
      "side_a_action": null,
      "side_b_action": "deny",
      "address_count": 65536,
      "range_count": 1,
      "cidrs": ["10.1.0.0/16"]
    }
  ],
  "merge_conflicts": null,
  "merged": null,
  "diff": null,
  "summary": {
    "structural_conflicts": 0,
    "action_conflict_ranges": 1,
    "action_conflict_addresses": 65536,
    "merge_conflict_ranges": null,
    "merge_conflict_addresses": null
  }
}
```

错误码（与 simulate 一致，复用同一套规则校验与异常格式）：

- 任一批次非法（未知/重复目标、add 撞基线 ID、单批删光、空批次等）→ `400`
  `invalid_simulation`，`issues` 一次性列出全部问题（A 先于 B 校验）；
- 批次内新增/替换规则 CIDR、action 非法 → `400 invalid_ruleset`；
- 字段层面错误（缺 `a`/`b`、未知顶层字段、操作对象多余字段、未知 action 等）→ `422`；
- 基准版本不存在 → `404`。

### 临时封禁方案预演（quarantine plan）

`POST /api/analyses/{id}/quarantine-plan` 在**已保存版本**之上，针对一个**严格 CIDR 目标**
（主机位必须为 0、必须显式带前缀长度）预演一组"临时封禁"规则：服务端按现有**最长前缀匹配
（LPM）+ 同网段优先级裁决**，确定性地生成一份 **`priority=0` 的 deny 新增规则清单**，使
**目标网段内当前 `permit` 或未匹配（`none`）的地址块全部转为 deny**，而**目标外的最终动作
完全不变**。与 simulate/merge-precheck 一样，本端点**只预演，不保存版本、不写库**。

请求体：

| 字段 | 说明 |
| --- | --- |
| `cidr` | **严格 CIDR** 目标网段（IPv4/IPv6 均可），主机位为 0、必须显式带前缀长度 |
| `rule_id_prefix` | 新规则 ID 前缀（非空字符串）；生成的 ID 为 `<前缀>1, <前缀>2, ...` 连续序号 |

生成规则（全部是**纯网段几何运算**，IPv4/IPv6 各自独立、不枚举地址）：

- 目标先按该版本的决策地图切成互不重叠、合起来无遗漏的常量动作分块；
- **已经是 deny 的地址块不生成任何规则**；
- `permit` 或未匹配（`none`）的块放一条 `priority=0` 的 deny 规则：
  - 胜出规则在**更短前缀**（严格父网段）上时，新规则凭**更长前缀**直接胜出，与对方优先级无关；
  - 块 CIDR 与现有胜出规则**同网段**时，仅当现有规则 `priority > 0` 才能在同网段裁决中胜出；
- 遇到**同网段 `priority=0` 的原规则**（permit）时，同网段 deny 无法靠优先级胜出，于是把该块
  **细分**为前缀长度 +1 的两半后分别重新裁决——两半都是更长前缀，落在其外层裁决上，新放的
  deny 规则凭 LPM 胜出；细分沿真实的内部规则 CIDR 递归（不会漏掉更深的规则）；
- 细分到**单地址**（IPv4 `/32`、IPv6 `/128`）仍被一条 `priority=0` 的非 deny 原规则占住时，
  任何 CIDR 规则都无法胜出：返回 `generated: false`，并在 `blocking` 中逐地址报告
  **不可生成地址与阻碍网段**（`blocking_rule_id` / `blocking_cidr` / `blocking_priority` 等），
  此时**不返回任何半成品规则**（all-or-nothing）。

生成成功后，服务端会把新规则追加到基线输入**用真实分析器重算候选**，再用**语义差异能力**
逐地址复核：所有变化都必须是"转 deny"且完全落在目标内，并最终用候选版本的决策地图确认
**目标内 100% 为 deny**。响应里给出规则清单、**目标内实际转为 deny 的最小 CIDR
（`quarantined_cidrs`）与精确地址数**（已经 deny 的部分不重复计算）、候选完整分析与相对
基线的语义差异。生成规则的 `source_tag` 固定为 `quarantine-plan`。

```bash
curl -s -X POST http://localhost:8080/api/analyses/an_e38b58f57faf2325/quarantine-plan \
  -H 'Content-Type: application/json' \
  -d '{"cidr": "10.10.0.0/16", "rule_id_prefix": "quar-"}'
```

上例基线为 `permit 10.0.0.0/8 → deny 10.10.0.0/16 → permit 10.10.1.0/24`：/16 内除
permit /24 洞之外都已是 deny，因此只生成一条规则，实际转 deny 的就是那个 /24 洞。响应：

```json
{
  "analysis_id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "base": {"id": "an_e38b58f57faf2325", "ruleset_hash": "e38b58f5...", "analyzer_version": "1.0.0"},
  "target_cidr": "10.10.0.0/16",
  "ip_version": 4,
  "rule_id_prefix": "quar-",
  "generated": true,
  "new_rules": [
    {
      "rule_id": "quar-1",
      "cidr": "10.10.1.0/24",
      "action": "deny",
      "priority": 0,
      "source_tag": "quarantine-plan",
      "address_count": 256,
      "from_action": "permit",
      "supersedes_rule_id": "r3",
      "subdivision_of_rule_id": null
    }
  ],
  "new_rule_count": 1,
  "blocking": [],
  "candidate": {
    "analyzer_version": "1.0.0",
    "ruleset_hash": "9d31...（候选输入的哈希，仅用于本次响应）",
    "id": null,
    "name": null,
    "persisted": false,
    "summary": {"rule_count": 5, "...": "..."},
    "rules": ["...完整规则结果（含新增的 quar-1）..."],
    "findings": ["..."],
    "minimal_conflict_pairs": ["..."]
  },
  "diff": {
    "base":   {"id": "an_e38b58f57faf2325", "ruleset_hash": "e38b58f5...", "analyzer_version": "1.0.0"},
    "target": {"id": null, "ruleset_hash": "9d31...", "analyzer_version": "1.0.0"},
    "changes": [
      {"ip_version": 4, "change_type": "permit_to_deny",
       "from_action": "permit", "to_action": "deny",
       "address_count": 256, "range_count": 1, "cidrs": ["10.10.1.0/24"]}
    ],
    "summary": {"...": "与版本语义差异相同的分类计数..."}
  },
  "quarantined_cidrs": ["10.10.1.0/24"],
  "quarantined_range_count": 1,
  "quarantined_addresses": 256,
  "already_deny_addresses": 65280,
  "summary": {
    "target_addresses": 65536,
    "already_deny_addresses": 65280,
    "before_permit_addresses": 256,
    "before_none_addresses": 0,
    "planned_new_rules": 1,
    "quarantined_addresses": 256,
    "quarantined_ranges": 1,
    "final_deny_addresses": 65536,
    "final_permit_addresses": 0,
    "final_none_addresses": 0,
    "total_changed_addresses": 256
  }
}
```

**同网段 `priority=0` 细分示例**：基线为 `permit(priority=0) 10.0.0.0/24`，对该 /24 生成方案时
同网段规则无法胜出，细分为两个 /25，各放一条 deny（其 `subdivision_of_rule_id` 指向被绕过的
原规则）：

```json
{
  "generated": true,
  "new_rules": [
    {"rule_id": "q1", "cidr": "10.0.0.0/25", "action": "deny", "priority": 0,
     "from_action": "permit", "supersedes_rule_id": "r1", "subdivision_of_rule_id": "r1", "...": "..."},
    {"rule_id": "q2", "cidr": "10.0.0.128/25", "action": "deny", "priority": 0,
     "from_action": "permit", "supersedes_rule_id": "r1", "subdivision_of_rule_id": "r1", "...": "..."}
  ],
  "quarantined_cidrs": ["10.0.0.0/24"],
  "quarantined_addresses": 256
}
```

**不可生成示例**（`/24` 内有一条占住单地址的 `priority=0` permit /32）返回 `200` 且
`generated: false`，`new_rules` 为空、`candidate`/`diff` 为 `null`，`blocking` 给出阻碍地址：

```json
{
  "generated": false,
  "new_rules": [],
  "new_rule_count": 0,
  "blocking": [
    {
      "cidr": "10.0.0.5/32",
      "ip_version": 4,
      "address_count": 1,
      "blocking_cidr": "10.0.0.5/32",
      "blocking_rule_id": "r2",
      "blocking_action": "permit",
      "blocking_priority": 0,
      "reason": "single-address block 10.0.0.5/32 is held by priority-0 rule 'r2' (permit) on 10.0.0.5/32; a deny rule cannot outrank it at the same prefix and no longer prefix exists"
    }
  ],
  "candidate": null,
  "diff": null,
  "quarantined_cidrs": [],
  "quarantined_addresses": 0,
  "already_deny_addresses": 0,
  "summary": {
    "target_addresses": 256,
    "already_deny_addresses": 0,
    "before_permit_addresses": 256,
    "before_none_addresses": 0,
    "planned_new_rules": 0,
    "blocking_range_count": 1,
    "blocking_addresses": 1,
    "quarantined_addresses": 0
  }
}
```

错误码：

- 生成的 ID（`<前缀>1, <前缀>2, ...`）**撞上基线中已有 rule_id** → `400`，形如
  `{"error": "invalid_quarantine_plan", "detail": "generated rule_id(s) collide ...: q1; ..."}`
  （一次性列出所有撞号的生成 ID，换一个前缀即可）；
- 目标 CIDR 非法（主机位非零、缺前缀长度等）→ `400 invalid_cidr`（先校验 CIDR，再查版本）；
- 字段层面错误（缺 `cidr`/`rule_id_prefix`、前缀为空白、多余字段等）→ `422`；
- 基准版本不存在 → `404`。

预演是只读的：重复调用结果完全确定（相同规则集、相同目标与前缀得到相同 ID 序列与
`ruleset_hash`），数据库不新增任何分析版本，发布指针不变。

### 访问观测归因（traffic audit）

`POST /api/analyses/{id}/traffic-audit` 在**已保存版本**之上，把一批**观测到的访问记录**
逐条归因到"本应裁决它"的规则，并核对观测动作与预期动作是否一致。与 decision-map 一样，
本端点**只读取该版本已保存的规则**：不重跑分析器、不新建分析版本、不写库。

请求体（`records` 为**非空数组**）：

| 字段 | 说明 |
| --- | --- |
| `ip` | 观测到的 IPv4/IPv6 **地址**（单个地址，不带前缀长度；`10.0.0.0/24` 这类写法会被拒绝） |
| `action` | 实际观测到的动作 `permit`/`deny`（别名同规则：`allow`/`accept`/`pass`、`block`/`drop`/`reject`，大小写不敏感） |
| `count` | 可选**正整数**次数（权重），默认 `1`；`0`、负数、布尔、浮点、字符串都会被拒绝 |

归因语义（与分析引擎的转发裁决完全一致，**绝不按记录顺序或"第一条命中的规则"归因**）：

1. **最长前缀胜出**：在覆盖该地址的同族规则中取前缀最长者——即使短前缀规则提交在前；
2. **同 CIDR 并列**按 `priority`（数字小者胜）再按**原提交顺序**裁决，落选的 duplicate
   永远不会被归因；
3. **没有任何规则覆盖的地址明确标为 `uncovered`**：`matched_rule_id` / `expected_action` /
   `consistent` 均为 `null`，**不会**被推断成 permit 或 deny，也不计入一致/不一致。

响应逐条返回（`results`，按输入顺序，`seq` 为从 0 起的序号）：命中规则
`matched_rule_id`、预期动作 `expected_action`、一致性（`verdict` 三态
`consistent`/`mismatch`/`uncovered` 与可空布尔 `consistent`）。加权次数（`count` 之和）
分三个维度汇总：

- `by_rule`：按**胜出规则**分组的记录条数与加权次数（含一致/不一致拆分），按加权次数降序；
- `mismatches`：**动作不一致**按（规则、预期动作、观测动作）分组的加权次数；
- `uncovered`：**未覆盖**按（IP 族、观测动作）分组的加权次数；
- `summary`：总条数/总加权次数、覆盖与未覆盖、一致与不一致、IPv4/IPv6 各自的汇总。

```bash
curl -s -X POST http://localhost:8080/api/analyses/an_e38b58f57faf2325/traffic-audit \
  -H 'Content-Type: application/json' \
  -d '{
    "records": [
      {"ip": "10.10.1.7",  "action": "permit", "count": 3},
      {"ip": "10.10.1.7",  "action": "deny"},
      {"ip": "10.10.2.9",  "action": "permit", "count": 2},
      {"ip": "10.20.0.4",  "action": "permit"},
      {"ip": "192.0.2.8",  "action": "deny"},
      {"ip": "2001:db8::1", "action": "deny",  "count": 5}
    ]
  }'
```

以上文 `dc-2026-09` 版本（`permit 10.0.0.0/8 → deny 10.10.0.0/16 → permit 10.10.1.0/24`，
另有 `deny 2001:db8::/32`）为例，响应（节选）：

```json
{
  "analysis_id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "record_count": 6,
  "results": [
    {"seq": 0, "ip": "10.10.1.7", "ip_version": 4, "observed_action": "permit", "count": 3,
     "verdict": "consistent", "matched_rule_id": "r3", "expected_action": "permit", "consistent": true},
    {"seq": 1, "ip": "10.10.1.7", "ip_version": 4, "observed_action": "deny", "count": 1,
     "verdict": "mismatch", "matched_rule_id": "r3", "expected_action": "permit", "consistent": false},
    {"seq": 2, "ip": "10.10.2.9", "ip_version": 4, "observed_action": "permit", "count": 2,
     "verdict": "mismatch", "matched_rule_id": "r2", "expected_action": "deny", "consistent": false},
    {"seq": 4, "ip": "192.0.2.8", "ip_version": 4, "observed_action": "deny", "count": 1,
     "verdict": "uncovered", "matched_rule_id": null, "expected_action": null, "consistent": null}
  ],
  "by_rule": [
    {"rule_id": "r4", "action": "deny", "records": 1, "count": 5,
     "consistent_count": 5, "mismatch_count": 0},
    {"rule_id": "r3", "action": "permit", "records": 2, "count": 4,
     "consistent_count": 3, "mismatch_count": 1},
    {"rule_id": "r2", "action": "deny", "records": 1, "count": 2,
     "consistent_count": 0, "mismatch_count": 2},
    {"rule_id": "r1", "action": "permit", "records": 1, "count": 1,
     "consistent_count": 1, "mismatch_count": 0}
  ],
  "mismatches": [
    {"rule_id": "r2", "expected_action": "deny", "observed_action": "permit", "records": 1, "count": 2},
    {"rule_id": "r3", "expected_action": "permit", "observed_action": "deny", "records": 1, "count": 1}
  ],
  "uncovered": [
    {"ip_version": 4, "observed_action": "deny", "records": 1, "count": 1}
  ],
  "summary": {
    "record_count": 6, "total_count": 13,
    "covered": {"records": 5, "count": 12},
    "uncovered": {"records": 1, "count": 1},
    "consistent": {"records": 3, "count": 9},
    "mismatch": {"records": 2, "count": 3},
    "ipv4": {"records": 5, "count": 8},
    "ipv6": {"records": 1, "count": 5}
  }
}
```

注意 `10.10.2.9` 归因到 `deny 10.10.0.0/16`（r2）而非提交在前的 `permit 10.0.0.0/8`
（r1）——最长前缀优先；`192.0.2.8` 没有任何规则覆盖，明确标为 `uncovered`。

错误码：

- 任一记录的 `ip` 非法（语法错误、带前缀长度等）→ **整批拒绝** `400`，形如
  `{"error": "invalid_traffic_audit", "detail": "...", "issues": ["record #1: ...", "..."]}`
  （`issues` 一次性列出全部非法记录）；
- 字段层面错误（未知动作、`count` 非正整数、缺字段、多余字段、`records` 为空等）→ `422`；
- 版本不存在 → `404`。

归因是只读的：重复调用结果完全确定，数据库不新增任何分析版本，发布指针不变。

### 观测纠偏（observation correction）

`POST /api/analyses/{id}/observation-correction` 在**已保存版本**之上，给定一批
**观测纠偏目标**——每条是一个 IP 与它**应当命中的动作**（`permit`/`deny`）——以及
一组允许改动的**候选规则**（`candidate_rule_ids`），搜索一个使全部观测在按现有
**最长前缀匹配（LPM）+ 同前缀优先级**重算后都命中期望动作的最小改动方案。与
traffic-audit 一样，本端点全程**只读**：不重跑分析器做持久化、不新建分析版本、不写库。

请求体：

| 字段 | 说明 |
| --- | --- |
| `observations` | **1～20 条**观测，非空且有上界；每条含 `ip`（IPv4/IPv6 **地址**，不带前缀长度）与 `action`（期望动作 `permit`/`deny`，别名同规则，大小写不敏感） |
| `candidate_rule_ids` | **1～8 个互异、存在于该版本**的 `rule_id`；响应中按 `rule_id` 排序返回，与提交顺序无关 |

每条候选规则在方案中恰好接受三种操作之一：

- **`keep`（保持）**：规则原样不动（不出现在 `operations` 中，仅计入 `kept_count`）；
- **`disable`（停用）**：把该规则从重算规则集中移除——其让出的范围可能回落到祖先规则，
  同 CIDR 落选的 duplicate 也可能接管；
- **`flip`（翻转）**：原地把动作取反（`permit` ↔ `deny`），CIDR、`priority`、
  `source_tag` 与提交位置均不变。

候选至多 8 个，解空间至多 `3^8 = 6561` 种组合，服务端直接**全量枚举**，每种组合都按与
引擎完全一致的 LPM + 同前缀优先级裁决（最长前缀胜出；同 CIDR 按 `priority` 数字小者、
再按原提交顺序）逐条重算观测的胜出规则。择优顺序为：

1. **改动规则数最少**（`disable` + `flip` 计数最小）；
2. 并列时**停用数最少**（能翻转胜出规则解决的，不停用它）；
3. 仍并列时，取候选按 `rule_id` 升序排列后，由 `(rule_id, operation)` 组成序列的
   **字典序最小**者（操作按字母序 `disable < flip < keep`，即第一个不同的候选取字母序
   最小的操作）。

**未命中不能视为 permit（也不视为 deny）**：某条观测在重算后没有任何存活规则覆盖时，
结果为 `matched_rule_id: null`、`action: null`，只有期望动作无法被满足。由于三种操作都
不会新增覆盖，一条本就未命中的观测无论期望什么动作都无法满足，整体返回无解。

响应：

- `solvable: true` 时给出 `plan`：`operations`（仅含非 keep 操作，候选按 `rule_id`
  排序；每条含 `from_action`，`flip` 另含 `to_action`、`disable` 的 `to_action` 为
  `null`）与 `changed_rule_count` / `disabled_count` / `flipped_count` / `kept_count`；
  `observations` 按输入顺序（`seq` 从 0 起）返回每条观测重算后的 `matched_rule_id`、
  `action` 与 `satisfied`。
- **原本全部符合**（不做任何改动即满足全部观测）→ `operations` 为空、
  `changed_rule_count: 0`（空方案）。
- **无解**（没有任何组合能让全部观测命中期望动作）→ `solvable: false`，
  `plan` 与 `observations` 均为 `null`。

```bash
curl -s -X POST http://localhost:8080/api/analyses/an_e38b58f57faf2325/observation-correction \
  -H 'Content-Type: application/json' \
  -d '{
    "observations": [
      {"ip": "10.10.1.7", "action": "deny"},
      {"ip": "10.10.2.9", "action": "deny"}
    ],
    "candidate_rule_ids": ["r1", "r2", "r3"]
  }'
```

以上文 `dc-2026-09` 版本（`permit 10.0.0.0/8 → deny 10.10.0.0/16 → permit 10.10.1.0/24`）
为例：`10.10.1.7` 命中 permit 的 r3、期望 deny，翻转 r3 即可；`10.10.2.9` 本就命中 deny
的 r2，无需改动。方案只翻转一条规则：

```json
{
  "analysis_id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "analyzer_version": "1.0.0",
  "observation_count": 2,
  "candidate_rule_ids": ["r1", "r2", "r3"],
  "solvable": true,
  "plan": {
    "operations": [
      {"rule_id": "r3", "operation": "flip", "from_action": "permit", "to_action": "deny"}
    ],
    "changed_rule_count": 1,
    "disabled_count": 0,
    "flipped_count": 1,
    "kept_count": 2
  },
  "observations": [
    {"seq": 0, "ip": "10.10.1.7", "ip_version": 4, "expected_action": "deny",
     "matched_rule_id": "r3", "action": "deny", "satisfied": true},
    {"seq": 1, "ip": "10.10.2.9", "ip_version": 4, "expected_action": "deny",
     "matched_rule_id": "r2", "action": "deny", "satisfied": true}
  ]
}
```

**原本全符合 → 空方案**（把上例第一条期望改回 permit）：

```json
{
  "solvable": true,
  "plan": {"operations": [], "changed_rule_count": 0,
           "disabled_count": 0, "flipped_count": 0, "kept_count": 3},
  "observations": ["...每条 satisfied: true，胜出规则与现网一致..."]
}
```

**停用回落到祖先**与**无解**示例：在同一版本上

- `{"ip": "10.10.2.9", "action": "permit"}` + 候选 `["r2"]`：r2 当前 deny；
  **翻转 r2**（r2 仍为胜出规则、动作变 permit）与**停用 r2**（回落到 permit 的 r1）都只
  改动一条规则，按**停用数最少**取 `flip`，重算后仍由 r2 胜出但动作变 permit；
- `{"ip": "192.0.2.9", "action": "permit"}` + 任意候选：该地址本就**未命中**，三种操作
  都不会新增覆盖，未命中不视为 permit，故返回 `solvable: false`、`plan: null`；
- `{"ip": "10.10.2.9", "action": "permit"}` + 候选 `["r1", "r3"]`：该地址由不在候选中的
  r2（deny /16）裁决，候选祖先与 /24 规则都无法改变它，返回无解。

```json
{
  "analysis_id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "analyzer_version": "1.0.0",
  "observation_count": 1,
  "candidate_rule_ids": ["r1", "r3"],
  "solvable": false,
  "plan": null,
  "observations": null
}
```

错误码：

- 任一观测的 `ip` 非法（语法错误、带前缀长度等）、或候选 `rule_id` 重复/在该版本不存在
  → **整批拒绝** `400`，形如
  `{"error": "invalid_observation_correction", "detail": "...", "issues": ["...全部问题..."]}`
  （观测问题按序号在前、候选问题随后，一次性列出）；
- 字段层面错误（未知动作、观测数为 0 或超过 20、候选数为 0 或超过 8、候选为空白、
  缺字段/多余字段等）→ `422`；
- 版本不存在 → `404`。

纠偏是只读的：重复调用结果完全确定（相同版本、相同观测与候选得到相同方案与逐条重算
结果），数据库不新增任何分析版本，发布指针不变，被纠偏版本的规则也不被修改。

### 已保存版本的 CIDR 决策地图（decision map）

针对**已保存版本**（不会新建分析、不写库），给定一个严格的 IPv4/IPv6 CIDR 查询
（主机位必须为 0、必须带前缀长度），以**纯网段运算**把查询范围切成**互不重叠、
合起来无遗漏的最小 CIDR 分块**。每个分块给出：

- `address_count`：该块地址数（IPv6 大整数精确给出，不枚举地址）；
- `action`：该块的**最终生效动作** `permit`/`deny`；没有任何规则命中时为 `null`（即 `none`）；
- `winner_rule_id` / `winner_source_tag`：胜出规则；未命中块均为 `null`；
- `match_chain`：**完整匹配链**——所有覆盖该块地址的规则，按**前缀由长到短**排列；
  同一 CIDR 的多条规则按 `priority`（数字小者在前）再按**原提交顺序**排列，因此
  **有匹配时首项即胜出规则**；同 CIDR 落选的重复规则（`role: "duplicate"`，含被完全
  遮蔽的祖先）也保留在链中；**未命中块返回空链 `[]`**。

**相邻且胜出规则相同**的分块会合并（`none` 块之间同样合并；胜出规则不同、或中间
隔着其他块的绝不合并），结果按网络地址、前缀长度**稳定排序**。分块依据是该版本
已保存的 winner 规则 `effective_cidrs`，与 diff 端点一致，IPv6 全空间 `::/0` 查询
也能精确处理。

```bash
curl -s "http://localhost:8080/api/analyses/an_e38b58f57faf2325/decision-map?cidr=10.10.0.0/16"
```

响应（节选）：

```json
{
  "analysis_id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "query_cidr": "10.10.0.0/16",
  "ip_version": 4,
  "summary": {
    "block_count": 9,
    "matched_blocks": 9,
    "unmatched_blocks": 0,
    "matched_addresses": 65536,
    "unmatched_addresses": 0,
    "permit_addresses": 256,
    "deny_addresses": 65280,
    "total_addresses": 65536
  },
  "blocks": [
    {
      "cidr": "10.10.0.0/24",
      "ip_version": 4,
      "address_count": 256,
      "action": "deny",
      "winner_rule_id": "r2",
      "winner_source_tag": "dc1",
      "match_chain": [
        {"rule_id": "r2", "index": 1, "cidr": "10.10.0.0/16", "action": "deny",
         "priority": 500, "source_tag": "dc1", "role": "winner"},
        {"rule_id": "r1", "index": 0, "cidr": "10.0.0.0/8", "action": "permit",
         "priority": 100, "source_tag": "hq", "role": "winner"}
      ]
    },
    {
      "cidr": "10.10.1.0/24",
      "ip_version": 4,
      "address_count": 256,
      "action": "permit",
      "winner_rule_id": "r3",
      "winner_source_tag": "lab",
      "match_chain": [
        {"rule_id": "r3", "index": 2, "cidr": "10.10.1.0/24", "action": "permit",
         "priority": 900, "source_tag": "lab", "role": "winner"},
        {"rule_id": "r2", "...": "..."},
        {"rule_id": "r1", "...": "..."}
      ]
    }
  ]
}
```

查询范围完全落在规则覆盖之外时，得到单个未命中块：`action: null`、
`winner_rule_id: null`、`match_chain: []`；查询跨越规则边界（如用 `8.0.0.0/6`
查询一条 `10.0.0.0/8` 规则）时，规则两侧的未匹配区域各自合并为最小 CIDR。
该端点**只读取该版本**，重复调用无副作用。

错误码：

- CIDR 非法（语法错误、主机位非零如 `10.0.0.5/24`、缺少前缀长度如 `10.0.0.0`、
  地址族不合法等）→ `400`，形如
  `{"error": "invalid_cidr", "detail": "invalid CIDR '10.0.0.5/24' (...)"}`
  （先校验查询参数，再查版本）；缺少 `cidr` 参数 → `422`；
- 版本不存在 → `404`。

### 冗余规则盘点（redundant rules）

`GET /api/analyses/{id}/redundant-rules` 盘点已保存版本中**哪些规则可以单独删除**：
对每条规则，服务端把它从规则集中移除、对剩余规则**重新执行最长前缀裁决**，再与
原版本逐地址比较 IPv4/IPv6 的**最终生效动作**（`permit`/`deny`/`none`，与版本语义
差异同一套几何算法，不枚举地址）。只有**所有地址的动作都不变**时才标记
`safe_to_remove: true`——绝不只凭 `shadowed` 状态或同动作重叠直接推断：

- 完全遮蔽的规则总是可安全删除；但**未遮蔽**的规则也可能安全——例如它的整个范围
  恰好落回一个同动作祖先（`permit /8` 里的 `permit /16`）；
- 反过来，删除同 CIDR 的 **winner** 会让落选的 duplicate 接管整个网段，删除动作
  不同的祖先也会让后代范围改变动作——只有重算后的逐地址比较能覆盖这些情形。

每条规则按**原提交顺序**返回 `rule_id`、`safe_to_remove` 和精确的变更地址数
`changed_addresses`（IPv4 + IPv6 合计，IPv6 大整数精确给出）；单规则版本同样给出
正确结果（删除唯一规则后其全部范围变为 `none`）。盘点是**只读**的：不新建分析
版本、不写库，可安全重复调用。

```bash
curl -s "http://localhost:8080/api/analyses/an_e38b58f57faf2325/redundant-rules"
```

响应（上文 `dc-2026-09` 示例版本：每条规则都承载着至少一段地址的裁决）：

```json
{
  "analysis_id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "analyzer_version": "1.0.0",
  "summary": {"rule_count": 4, "safe_to_remove_count": 0},
  "rules": [
    {"rule_id": "r1", "safe_to_remove": false, "changed_addresses": 16711680},
    {"rule_id": "r2", "safe_to_remove": false, "changed_addresses": 65280},
    {"rule_id": "r3", "safe_to_remove": false, "changed_addresses": 256},
    {"rule_id": "r4", "safe_to_remove": false, "changed_addresses": 79228162514264337593543950336}
  ]
}
```

错误码：版本不存在 → `404`。

### 来源整组撤场预演（source retirement）

`GET /api/analyses/{id}/source-retirement` 回答"**某个来源（`source_tag`）的规则能不能整组
下线**"：对已保存版本中**每个不同的 `source_tag`**，把该来源的**全部规则按原顺序一次性
移除**，对剩余规则**重新执行最长前缀匹配（LPM）+ 同 CIDR 优先级裁决**，再与原版本逐地址
比较 IPv4/IPv6 的**最终生效动作**（`permit`/`deny`/`none`，复用版本语义差异的几何算法，
不枚举地址）。与冗余规则盘点一样，本端点**只读**：不新建分析版本、不写库、不修改基线，
可安全重复调用。

**整组判定绝不等于逐条判定之和**：即使该来源的每条规则**单独**删除都不影响任何地址，
整组删除仍可能改变裁决——因此每个来源都是独立重算，而不是把逐条删除的结果合并。典型场景：

- 同一 CIDR 上 winner 与落选 duplicate 同属一个来源：duplicate 单独删无影响，winner 单独删
  时 duplicate 还在、动作由它接管也可能无影响，但**两条一起删**整个网段立刻失去覆盖；
- 多条同动作规则互为兜底（被遮蔽的 deny /16 与盖住它的两个 deny /17 同一来源）：逐条删都
  安全，整组删后 /16 整体回落到异动作祖先。

返回顺序**固定**：来源按其在原提交顺序中**首次出现**的先后排列；每个来源的 `rule_ids`
按**原提交顺序**列出（与规则 ID 字典序无关）；`changes` 中六种动作转变的排列与版本语义
差异端点一致（`permit_to_deny` → `permit_to_none` → `deny_to_permit` → `deny_to_none`
→ `none_to_permit` → `none_to_deny`，仅列确有地址变化的类型，IPv4 在 IPv6 前）。

每个来源条目给出：

| 字段 | 说明 |
| --- | --- |
| `source_tag` | 来源标签（规则未填时为 `default`） |
| `rule_ids` | 撤场时将被一次性移除的全部规则 ID，**按原提交顺序** |
| `rule_count` | 该来源规则数 |
| `safe_to_retire` | 整组移除后是否**没有任何地址**改变最终动作（可整组撤场） |
| `changed_addresses` | 整组撤场后动作发生变化的精确地址数（IPv4 + IPv6，IPv6 大整数精确给出） |
| `changes` | 按六种动作转变归类的**最小 CIDR** 列表与精确地址数（结构同版本语义差异的 `changes`）；相邻同前缀兄弟块合并；撤场无影响时为 `[]` |
| `summary` | 该来源的 IPv4/IPv6 分项与六种转变的地址计数（与版本语义差异 `summary` 同构） |

**删光规则按全网未命中比较**：若版本只有一个来源（撤场后规则集为空），空集无法调用分析器，
服务端以"全部地址均为 `none`"的合成结果参与比较，因此该来源的全部覆盖都会以
`permit_to_none` / `deny_to_none` 出现在 `changes` 中。

```bash
curl -s "http://localhost:8080/api/analyses/an_79764e286d728b72/source-retirement"
```

以上文三条规则版本（`permit 10.0.0.0/8` 来自 **core**；`deny 10.1.0.0/16` 与
`permit 10.1.1.0/24` 同属 **edge**）为例，响应（节选）：

```json
{
  "analysis_id": "an_79764e286d728b72",
  "ruleset_hash": "79764e28...",
  "analyzer_version": "1.0.0",
  "summary": {"source_count": 2, "rule_count": 3, "safe_to_retire_count": 0},
  "sources": [
    {
      "source_tag": "core",
      "rule_ids": ["r1"],
      "rule_count": 1,
      "safe_to_retire": false,
      "changed_addresses": 16711680,
      "changes": [
        {"ip_version": 4, "change_type": "permit_to_none",
         "from_action": "permit", "to_action": null,
         "address_count": 16711680, "range_count": 8,
         "cidrs": ["10.0.0.0/16", "10.2.0.0/15", "10.4.0.0/14", "..."]}
      ],
      "summary": {"changed_addresses": 16711680, "change_groups": 1,
                  "ipv4": {"...": "..."}, "ipv6": {"...": 0}}
    },
    {
      "source_tag": "edge",
      "rule_ids": ["r2", "r3"],
      "rule_count": 2,
      "safe_to_retire": false,
      "changed_addresses": 65280,
      "changes": [
        {"ip_version": 4, "change_type": "deny_to_permit",
         "from_action": "deny", "to_action": "permit",
         "address_count": 65280, "range_count": 8,
         "cidrs": ["10.1.0.0/24", "10.1.2.0/23", "10.1.4.0/22", "..."]}
      ],
      "summary": {"changed_addresses": 65280, "change_groups": 1,
                  "ipv4": {"...": "..."}, "ipv6": {"...": 0}}
    }
  ]
}
```

注意 edge 的两个片段：撤场后 /16 失去 deny 与 permit /24，整个 /16（65536 个地址）回落到
core 的 permit /8——其中原 permit /24 洞（256 个地址）动作**不变**，故只有
65536 − 256 = 65280 个地址计入 `deny_to_permit`，且差异以 /24 洞之外的最小 CIDR 碎片表示。

**可整组撤场示例**：`permit 10.0.0.0/8`（core）内有一条 `permit 10.1.0.0/16`（edge），
edge 虽实际转发流量（并非 shadowed），但整组下线后其范围由**同动作祖先**接管，该来源条目的
`safe_to_retire: true`、`changed_addresses: 0`、`changes: []`：

```json
{
  "source_tag": "edge",
  "rule_ids": ["r2"],
  "rule_count": 1,
  "safe_to_retire": true,
  "changed_addresses": 0,
  "changes": [],
  "summary": {"changed_addresses": 0, "change_groups": 0,
              "ipv4": {"changed_addresses": 0, "change_groups": 0,
                       "by_type": {"permit_to_deny": 0, "permit_to_none": 0,
                                   "deny_to_permit": 0, "deny_to_none": 0,
                                   "none_to_permit": 0, "none_to_deny": 0}},
              "ipv6": {"...": "全 0"}}
}
```

**逐条安全 ≠ 整组安全示例**：同一 CIDR 上 `permit(priority=10)` 与 `deny(priority=20)` 同属
`hq` 来源时，冗余规则盘点中落选的 deny duplicate 可单独安全删除，但整组撤场会让整个
`172.16.0.0/12`（2²⁰ 个地址）从 permit 变为 `none`，因此 `safe_to_retire: false`，
`changes` 给出一组 `permit_to_none` 的最小 CIDR（此处即 `172.16.0.0/12` 本身）。

错误码：版本不存在 → `404`。

### 版本语义差异（semantic diff）

给定两个**已保存**版本 ID，逐地址比较它们的**最终生效动作**：地址落在某条 winner 规则的
`effective_cidrs` 内取该规则动作（`permit`/`deny`），没有任何规则匹配记为 `none`。差异按
六种变化类型分组——`permit_to_deny` / `permit_to_none` / `deny_to_permit` /
`deny_to_none` / `none_to_permit` / `none_to_deny`，每类给出**最小 CIDR 范围**与地址数量。

计算是纯几何的（CIDR 切割 + `ipaddress.collapse_addresses`），不枚举地址，IPv6 的超大空间
（2¹²⁸）也能精确处理。**仅合并变化类型相同且相邻（同前缀兄弟块）的范围**；类型不同、或中间
隔着未变化/空隙的范围不会合并。IPv4/IPv6 各自独立比较与汇总。

```bash
curl -s "http://localhost:8080/api/analyses/an_8914e028acea3413/diff/an_efdb05adb508e531"
```

响应（节选）：

```json
{
  "base":   {"id": "an_8914...", "ruleset_hash": "8914...", "analyzer_version": "1.0.0"},
  "target": {"id": "an_efdb...", "ruleset_hash": "efdb...", "analyzer_version": "1.0.0"},
  "changes": [
    {
      "ip_version": 4,
      "change_type": "deny_to_permit",
      "from_action": "deny", "to_action": "permit",
      "address_count": 65536, "range_count": 1,
      "cidrs": ["10.1.0.0/16"]
    }
  ],
  "summary": {
    "total_changed_addresses": 65536,
    "total_change_groups": 1,
    "ipv4": {"changed_addresses": 65536, "change_groups": 1,
             "by_type": {"permit_to_deny": 0, "permit_to_none": 0,
                         "deny_to_permit": 65536, "deny_to_none": 0,
                         "none_to_permit": 0, "none_to_deny": 0}},
    "ipv6": {"changed_addresses": 0, "change_groups": 0, "by_type": { "...": 0 }}
  }
}
```

语义相同（即使规则形状不同）的两个版本返回空 `changes`。错误码：

- ID 格式非法（不是 `an_` + 16 个小写十六进制字符）或两个 ID 相同 → `400`；
- 任一版本不存在 → `404`（先做格式/同一性校验，再查存在性）。

### 变更守卫（change guard）

`POST /api/analyses/{base}/change-guard/{target}` 在**版本语义差异**之上加一层授权核对：
请求体给出一组**授权条目**，服务端逐段检查 base→target 的每一处生效动作变化是否都落在
被授权的范围内，**不新建分析、不写库**。

```bash
curl -s -X POST http://localhost:8080/api/analyses/an_0a34f5ffbbdcf273/change-guard/an_e72f1fd559c70442 \
  -H 'Content-Type: application/json' \
  -d '{
    "authorizations": [
      {"cidr": "10.1.0.0/16", "from_action": "permit", "to_action": "deny"}
    ]
  }'
```

每个授权条目：

| 字段 | 说明 |
| --- | --- |
| `cidr` | **严格 CIDR**：必须显式带前缀长度、主机位为 0（`10.0.0.5/24`、`10.0.0.0` 都会被拒绝） |
| `from_action` / `to_action` | `permit` / `deny` / `none`（`none` = 无任何规则命中），大小写不敏感；**两者必须不同**（授权描述的是一次"变化"） |

核对语义：

- 地址发生动作变化时，只有落在**同 IP 家族且同动作转换**（`from_action`/`to_action` 完全一致）
  的授权 CIDR 内才算获准；IPv4 授权不能覆盖 IPv6 变化，`permit→deny` 的授权不能覆盖
  `deny→permit` 的变化；
- **同类**（同转换）授权可以随意嵌套、重复——按**并集**计算（相邻兄弟块也会合并）；
- **异类**授权的 CIDR 相互重叠（包含或相等）→ 整个请求 `400 invalid_change_guard`，
  `issues` 一次性列出全部问题；
- **没有发生变化的地址不需要授权**：授权条目覆盖了未变化区域不算违规，未被任何变化用到的
  授权条目直接忽略。

响应（上例：v1 = `permit 10.0.0.0/8`，v2 = `deny 10.1.0.0/16` + `permit 10.1.1.0/24`，
只授权了 `permit→deny`）：

```json
{
  "base":   {"id": "an_0a34...", "ruleset_hash": "0a34...", "analyzer_version": "1.0.0"},
  "target": {"id": "an_e72f...", "ruleset_hash": "e72f...", "analyzer_version": "1.0.0"},
  "passed": false,
  "violations": [
    {
      "ip_version": 4,
      "change_type": "permit_to_none",
      "from_action": "permit", "to_action": null,
      "unauthorized_address_count": 16711680,
      "unauthorized_range_count": 8,
      "unauthorized_cidrs": ["10.0.0.0/16", "10.2.0.0/15", "10.4.0.0/14", "..."]
    }
  ],
  "summary": {
    "authorization_entries": 1,
    "total_changed_addresses": 16776960,
    "total_authorized_addresses": 65280,
    "total_unauthorized_addresses": 16711680,
    "total_violation_groups": 1,
    "ipv4": {"changed_addresses": 16776960, "unauthorized_addresses": 16711680,
             "violation_groups": 1, "by_type": {"permit_to_deny": 0, "permit_to_none": 16711680, "...": 0}},
    "ipv6": {"changed_addresses": 0, "unauthorized_addresses": 0, "violation_groups": 0, "by_type": {"...": 0}}
  }
}
```

- `passed`：全部变化均被授权时为 `true`；
- `violations`：按转换类型分组的**未授权**范围——最小 CIDR 列表（`unauthorized_cidrs`）、
  精确地址数（`unauthorized_address_count`，IPv6 大整数精确给出）与段数；只列出确有未授权
  地址的转换，顺序与 diff 的六种变化类型一致；
- `summary`：变化/已授权/未授权地址总数，IPv4/IPv6 各自独立汇总（`by_type` 含全部六种转换）。

与 diff 一样，全部计算都是 CIDR 几何运算，不逐地址枚举，IPv6 全空间也能精确处理。错误码：

- ID 格式非法或两个 ID 相同 → `400`（先校验 ID，再校验授权条目，最后查存在性）；
- 授权 CIDR 非法、异类授权相互重叠 → `400`，形如
  `{"error": "invalid_change_guard", "detail": "...", "issues": ["...全部问题..."]}`；
- 字段层面错误（`from_action == to_action`、未知动作、空 `authorizations`、多余字段等）→ `422`；
- 任一版本不存在 → `404`。

### 发布指针（active pointer）

所有已保存版本之上维护一个**发布指针**，回答"当前对外发布的是哪一个分析版本"。服务首次
初始化时指针为：

```json
{"active_id": null, "revision": 0}
```

`revision` 是单调递增的乐观并发版本号：**每一次成功的 activate 都 +1**（即使目标与当前
版本相同，也视为一次新的发布动作）。指针**只能指向已保存版本**，不会引用未落库的预演/
合并结果。

#### 查看当前指针

```bash
curl -s http://localhost:8080/api/active
# {"active_id":"an_e38b58f57faf2325","revision":2}
```

#### 发布 / 切换版本

请求体：

| 字段 | 说明 |
| --- | --- |
| `analysis_id` | 要发布的**已保存版本** ID（`an_` + 16 个小写十六进制字符） |
| `expected_revision` | 调用方上一次 `GET /api/active` 看到的 revision；只有它与库中当前 revision **完全相等**时切换才会落地 |

核对 revision、更新指针、递增 revision、写入审计记录在**同一个 SQLite 写事务**
（`BEGIN IMMEDIATE`）内完成，因此并发发布会被串行化：同一个 revision 值下**只有一个请求
能成功**，后来者拿到 `409` 与当前最新状态，不会互相覆盖。

```bash
# 第一次发布：从 null/0 发布到 v1
curl -s -X POST http://localhost:8080/api/active/activate \
  -H 'Content-Type: application/json' \
  -d '{"analysis_id": "an_e38b58f57faf2325", "expected_revision": 0}'
```

成功响应（`200`）记录了切换后的状态与切换前状态：

```json
{
  "active": {
    "active_id": "an_e38b58f57faf2325",
    "revision": 1,
    "activated_at": "2026-09-24T08:30:00Z",
    "history_seq": 1
  },
  "previous": {"active_id": null, "revision": 0}
}
```

切换到另一个版本时带上当前 revision（上例之后为 `1`）：

```bash
curl -s -X POST http://localhost:8080/api/active/activate \
  -H 'Content-Type: application/json' \
  -d '{"analysis_id": "an_8914e028acea3413", "expected_revision": 1}'
# {"active": {"active_id": "an_8914e028acea3413", "revision": 2, "...": "..."},
#  "previous": {"active_id": "an_e38b58f57faf2325", "revision": 1}}
```

#### revision 冲突（409）

若在调用方读取状态之后已有别的发布成功（指针 revision 已经前进），本次激活被整体拒绝，
指针、revision 与历史均不变，响应体带回**当前状态**供调用方重新读取后重试：

```json
{
  "error": "revision_conflict",
  "detail": "expected_revision does not match the current pointer revision; refetch GET /api/active and retry",
  "current": {"active_id": "an_8914e028acea3413", "revision": 2}
}
```

#### 只读发布历史

```bash
curl -s "http://localhost:8080/api/active/history?limit=50&offset=0"
```

每次成功切换追加一条只增不改的审计记录（**新的在前**），包含前后版本、时间与 revision：

```json
{
  "total": 2,
  "history": [
    {"seq": 2, "revision": 2, "previous_id": "an_e38b58f57faf2325",
     "active_id": "an_8914e028acea3413", "activated_at": "2026-09-24T08:31:00Z"},
    {"seq": 1, "revision": 1, "previous_id": null,
     "active_id": "an_e38b58f57faf2325", "activated_at": "2026-09-24T08:30:00Z"}
  ]
}
```

历史为只读接口，没有任何写入/删除入口；`limit`（1–200，默认 50）与 `offset` 分页，
非法分页参数返回 `422`。

错误码：

- `analysis_id` 格式非法（不是 `an_` + 16 个小写十六进制字符）→ `400`；
- 目标版本未保存/不存在 → `404`（在开启写事务之前检查，且失败不推进 revision）；
- `expected_revision` 与当前 revision 不一致（并发发布落败）→ `409 revision_conflict`，
  响应中 `current` 为当前指针状态；
- 字段层面错误（缺字段、`expected_revision` 为负数、多余字段等）→ `422`。

### 错误处理

- 非法 CIDR（语法错误、主机位非零、rule_id 重复等）→ `400`，形如
  `{"error": "invalid_ruleset", "detail": "rule #1: invalid CIDR '10.0.0.5/24' (...)"}`
- 预演/合并预检批次非法（add 撞已有 ID、replace/remove 未命中基准、同一目标在单批内出现
  多次、单批删光所有规则、空批次等）→ `400`，形如
  `{"error": "invalid_simulation", "detail": "...", "issues": ["...全部问题..."]}`
  （合并预检中同一 `rule_id` 被 A、B 两批同时操作属于**语义冲突**，返回 `200` 且
  `passed: false`，不是 400）
- 决策地图 CIDR 查询非法（主机位非零、缺前缀长度等）→ `400`，形如
  `{"error": "invalid_cidr", "detail": "invalid CIDR '10.0.0.5/24' (...)"}`
- 变更守卫授权集非法（授权 CIDR 非严格 CIDR、异类授权相互重叠等）→ `400`，形如
  `{"error": "invalid_change_guard", "detail": "...", "issues": ["...全部问题..."]}`
- 临时封禁方案生成的 rule_id 撞上基线已有 ID → `400`，形如
  `{"error": "invalid_quarantine_plan", "detail": "generated rule_id(s) collide ...: q1; ..."}`
  （存在 `priority=0` 单地址阻碍时不是错误：返回 `200` 且 `generated: false`）
- 访问观测批次中存在非法 IP（语法错误、带前缀长度等）→ **整批拒绝** `400`，形如
  `{"error": "invalid_traffic_audit", "detail": "...", "issues": ["record #2: invalid IP address ..."]}`
- 观测纠偏请求中存在非法 IP，或候选 `rule_id` 重复/在该版本不存在 → **整批拒绝** `400`，形如
  `{"error": "invalid_observation_correction", "detail": "...", "issues": ["...全部问题..."]}`
  （观测/候选数超出 1～20 / 1～8 等字段约束为 `422`；无解不是错误，返回 `200` 且 `solvable: false`）
- 发布指针的 `expected_revision` 与当前 revision 不一致（并发发布冲突）→ `409`，形如
  `{"error": "revision_conflict", "detail": "...", "current": {"active_id": "...", "revision": 2}}`
- 字段类型/取值错误（未知 action、空规则列表、多余字段、缺少必填查询参数等）→ `422`（Pydantic 校验错误）
- 版本不存在 → `404`

---

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── analyzer.py      # 核心引擎：CIDR 解析、trie、覆盖与最小冲突对（纯函数，可独立使用）
│   ├── diff.py          # 版本语义差异：生效动作分区叠加 + 相邻同类范围合并（纯函数，可独立使用）
│   ├── change_guard.py  # 变更守卫：授权条目解析/并集/重叠校验 + 未授权范围切割（纯函数，可独立使用）
│   ├── decision_map.py  # 已保存版本的 CIDR 决策地图：查询网段切分 + 匹配链（纯函数，可独立使用）
│   ├── redundant.py     # 冗余规则盘点：逐条移除 + 重算 LPM + 语义差异比较（纯函数，可独立使用）
│   ├── source_retirement.py # 来源整组撤场预演：按 source_tag 一次性移除 + 重算 LPM + 语义差异比较（纯函数，可独立使用）
│   ├── simulate.py      # 变更预演：从已保存版本重建输入 + add/replace/remove 批次校验与打补丁（纯函数）
│   ├── merge_precheck.py # 双批次合并预检：两侧分别重算 + 改变范围精确叠加 + A 后 B 合并重算（纯函数，可独立使用）
│   ├── quarantine_plan.py # 临时封禁方案：决策分块 + p0 同网段细分 + 真实分析/语义差异复核（纯函数，可独立使用）
│   ├── traffic_audit.py   # 访问观测归因：单地址 LPM 裁决 + 一致性核对 + 加权汇总（纯函数，可独立使用）
│   ├── observation_correction.py # 观测纠偏：keep/disable/flip 全枚举 + 最少改动/最少停用/字典序择优（纯函数，可独立使用）
│   ├── schemas.py       # Pydantic v2 请求/响应模型
│   ├── db.py            # SQLite 持久层（analyses / rules / findings / active_pointer / active_history 五表）
│   └── main.py          # FastAPI 路由
├── tests/test_api.py           # 端到端测试（pytest + TestClient）
├── tests/test_active.py        # 发布指针与乐观锁（含并发发布）测试
├── tests/test_diff.py          # 语义差异端点测试
├── tests/test_change_guard.py  # 变更守卫端点测试
├── tests/test_decision_map.py  # CIDR 决策地图端点测试
├── tests/test_redundant_rules.py # 冗余规则盘点端点测试
├── tests/test_source_retirement.py # 来源整组撤场预演端点测试（首现顺序、整组重判、删空、IPv6、只读）
├── tests/test_simulate.py      # 规则变更预演端点测试
├── tests/test_merge_precheck.py # 双批次合并预检端点测试
├── tests/test_quarantine_plan.py # 临时封禁方案端点测试（细分、阻碍网段、ID 撞号、IPv6）
├── tests/test_traffic_audit.py  # 访问观测归因端点测试（LPM 归因、并列裁决、未覆盖、加权汇总、IPv6）
├── tests/test_observation_correction.py # 观测纠偏端点测试（翻转/停用、未命中不放行、三级择优、校验、只读）
├── requirements.txt
├── Dockerfile          # 非 root 运行、内置 HEALTHCHECK、暴露 8080
├── docker-compose.yml  # 单命令启动 + 命名卷持久化
└── README.md
```

### SQLite 表结构

- `analyses(id, name, ruleset_hash, analyzer_version, created_at, rule_count, result_json)`
  —— 不可变版本，完整结果 JSON 冗余保存，便于导出；
- `rules(analysis_id, rule_index, rule_id, cidr, ip_version, action, priority, source_tag,
  role, status, covered, has_conflict)` —— 支持 SQL 过滤；
- `findings(analysis_id, seq, kind, severity, rule_id, other_rule_id, behavioral, payload_json)`
  —— 支持按严重级别/是否影响行为过滤；
- `active_pointer(id, active_id, revision)` —— 单行（`id = 1`）发布指针，初始化时为
  `active_id = NULL`、`revision = 0`；`active_id` 外键指向 `analyses(id)`，因此只能发布
  已保存版本；
- `active_history(seq, revision, previous_id, active_id, activated_at)` —— 只增不改的发布
  审计表：每次成功切换在同一事务内追加一行，记录前一版本/新版本、新 revision 与 UTC 时间，
  支持只读分页查询。

发布切换在单个 `BEGIN IMMEDIATE` 写事务内"读取当前 revision → 与 `expected_revision` 比较
→ 更新指针并 +1 → 追加历史"，并发发布由 SQLite 写锁串行化，revision 不匹配的请求得到
`409`，保证不会互相覆盖。

`covered` 以十进制文本存储，以容纳超出 64 位整数范围的 IPv6 地址计数（如 /32 的 2^96）。

### 确定性 / 幂等

版本 ID = `an_` + `sha256(规范化输入)` 的前 16 个十六进制字符。规范化输入包含
`rule_id / cidr / action / priority / source_tag`，与提交顺序无关地以规范 JSON
（排序键、无空白）序列化。重复提交同一规则集返回**同一个版本 ID**，数据库中只存一份。

### 复杂度

trie 构建对每个节点线性扫描候选祖先，复杂度约 O(n²)，适合数百至数千条规则的策略集；
覆盖差集基于标准库 `ipaddress.address_exclude`。若需要超大规模（数万条以上），可将
祖先查找替换为按版本分组的 radix tree，分析器输出契约不变。
