# Design: 日誌異常關聯偵測引擎 (LACE)

## Technical Approach

單一 Python 套件，無外部資料庫依賴，純本地檔案輸入輸出。核心資料流：

```
raw log file(s)
      │
      ▼
 ┌─────────────┐   任一格式 → 統一成 NormalizedEvent
 │  Parsers    │   (syslog_parser / csv_parser / jsonl_parser)
 └──────┬──────┘
        ▼
 ┌─────────────┐   依 src_ip 分組，事件依 timestamp 排序後
 │  Windower   │   逐筆推入每個 src_ip 專屬的 deque 滑動窗口
 └──────┬──────┘
        ▼
 ┌─────────────┐   四個 Detector 各自對窗口內事件跑規則
 │  Detectors  │   port_scan / brute_force / beaconing / exfil_volume
 └──────┬──────┘
        ▼ Finding[]
 ┌─────────────┐   比對本地 IOC 清單，補充信譽標籤
 │  Enricher   │
 └──────┬──────┘
        ▼ Finding[] (with reputation tags)
 ┌─────────────┐   同一 src_ip 的 Finding 合併成 Alert，
 │ Correlator  │   計算風險分數、去重
 └──────┬──────┘
        ▼ Alert[]
 ┌─────────────┐
 │  Reporters  │   json_reporter (機器可讀) / table_reporter (CLI 摘要)
 └─────────────┘
```

## Architecture Decisions

### Decision: 用 `collections.deque` 做每來源 IP 的滑動時間窗，不引入 pandas

- 事件量級是單機批次分析（數萬到數十萬筆），不需要 DataFrame 的開銷。
- `deque(maxlen=None)` 搭配左側依時間戳記淘汰（`while window[0].ts < now - window_seconds: window.popleft()`）
  即可達成 O(1) 攤銷成本的滑動窗口，且行為對每個 detector 都一致、容易單元測試。
- 保留最少依賴（僅 `pyyaml` 用於設定檔、`pydantic` 用於設定驗證與資料模型），
  符合 lite spec 精神，也讓工具在受限的內網主機上容易部署。

### Decision: Detector 介面統一為 `detect(window: list[NormalizedEvent], config: RuleConfig) -> list[Finding]`

- 四個 detector 彼此獨立、互不知道對方存在，方便未來新增第五種規則時不用動到
  既有程式碼（開閉原則）。
- 每個 Finding 必須包含：`rule_id`、`src_ip`、`window_start`、`window_end`、
  `evidence`（觸發依據的原始事件摘要，用於人工覆核）、`severity`（LOW/MEDIUM/HIGH）。

### Decision: Beaconing 偵測用「連續事件間隔的變異係數 (coefficient of variation)」而非固定週期比對

- 真實 C2 回連間隔會有抖動（jitter），單純比對「每隔剛好 60 秒」會漏掉大部分
  案例。改用 `stdev(intervals) / mean(intervals) < threshold`（例如 0.15）搭配
  最少事件數門檻（例如窗口內至少 6 次連線），可以同時容忍合理抖動又濾掉隨機流量。
- 這是本次唯一涉及基礎統計的規則，其餘三個 detector 都是純計數 + 門檻比對，
  讓整體複雜度可控。

### Decision: Correlator 用加權加總 + 上限封頂做風險分數，不做多變數模型

- `risk_score = min(100, Σ(rule_weight[rule_id] for each unique rule triggered) + ioc_bonus)`
- 同一規則在同一來源 IP 短時間內多次觸發只計一次權重（避免洗分數），但會把
  觸發次數記錄在 Alert 的 `hit_count` 供人工判讀嚴重度。
- 之所以不做加權平均或機率模型，是因為輸入資料量與雜訊程度在初期未知，先用
  可解釋、可手動調整權重的簡單公式，方便資安人員直接在 YAML 裡調參，之後有
  足夠標註資料再考慮更複雜的模型（不在本次範圍內）。

### Decision: 設定檔用 YAML + pydantic 做 schema 驗證，啟動時就 fail-fast

- 門檻值、視窗秒數、路徑等如果打錯字或型別不對，應該在程式一啟動就報錯並
  指出哪個欄位有問題，而不是跑到一半才因為 `None` 或字串型別炸掉。

## Data Flow / Module Layout

```
lace/
├── __init__.py
├── cli.py                 # argparse 入口，讀取 --config / --input / --output
├── config.py               # pydantic Settings 模型 + YAML 載入與驗證
├── models.py                # NormalizedEvent, Finding, Alert dataclass/pydantic 模型
├── parsers/
│   ├── __init__.py
│   ├── syslog_parser.py
│   ├── csv_parser.py
│   └── jsonl_parser.py
├── windowing.py             # 每 src_ip 滑動窗口管理
├── detectors/
│   ├── __init__.py
│   ├── base.py               # Detector 介面
│   ├── port_scan.py
│   ├── brute_force.py
│   ├── beaconing.py
│   └── exfil_volume.py
├── enrichment.py             # IOC 清單載入與比對
├── correlation.py            # Finding → Alert 聚合與風險分數計算
└── reporters/
    ├── __init__.py
    ├── json_reporter.py
    └── table_reporter.py

tests/
├── fixtures/
│   ├── sample_syslog.log
│   ├── sample_firewall.csv
│   ├── sample_events.jsonl
│   └── sample_ioc_list.csv
├── test_parsers.py
├── test_windowing.py
├── test_detectors.py
├── test_enrichment.py
├── test_correlation.py
└── test_cli_end_to_end.py
```

## File Changes

全部為新增檔案（本改動不修改任何既有系統，屬全新獨立工具）：

- `lace/` 套件全部檔案（如上）
- `tests/` 全部檔案（如上）
- `config.example.yaml`（範例設定檔，含所有門檻值與註解說明）
- `pyproject.toml`（套件定義、依賴：`pyyaml`, `pydantic>=2`, `pytest` for dev）
- `README.md`（安裝、設定檔說明、CLI 用法範例、輸出格式範例）
