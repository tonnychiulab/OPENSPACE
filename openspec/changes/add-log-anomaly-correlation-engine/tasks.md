# Tasks

## 1. 專案骨架與設定

- [x] 1.1 建立 `pyproject.toml`，宣告套件 `lace`、依賴 `pyyaml`、
      `pydantic>=2`，dev 依賴 `pytest`
- [x] 1.2 建立 `lace/` 套件目錄與各子模組空檔案（依 design.md 的
      module layout）
- [x] 1.3 撰寫 `config.example.yaml`，涵蓋四個 detector 的門檻值、
      各自的 `window_seconds`、規則權重、`ioc_bonus`、
      IOC 清單路徑、輸入輸出預設路徑，每個欄位都要有註解
- [x] 1.4 在 `lace/config.py` 用 pydantic 定義 `Settings` 模型與各
      detector 的子設定模型，實作 `load_settings(path) -> Settings`，
      驗證失敗時拋出附帶欄位名稱的清楚錯誤

## 2. 資料模型

- [x] 2.1 在 `lace/models.py` 定義 `NormalizedEvent`
      （`timestamp`, `src_ip`, `dst_ip`, `dst_port`, `protocol`,
      `bytes_out`, `event_type`, 原始行內容保留供除錯）
- [x] 2.2 定義 `Finding`（`rule_id`, `src_ip`, `window_start`,
      `window_end`, `evidence: dict`, `severity`, `reputation_tags`）
- [x] 2.3 定義 `Alert`（`src_ip`, `risk_score`, `triggered_rules`,
      `hit_count: dict[str, int]`, `reputation_tags`, `first_seen`,
      `last_seen`）

## 3. 日誌解析器

- [x] 3.1 實作 `parsers/csv_parser.py`：可設定欄位對應
      （column mapping），逐列轉為 `NormalizedEvent`
- [x] 3.2 實作 `parsers/jsonl_parser.py`：逐行解析 JSON，單行失敗
      不中斷整體流程，累積 parse error 計數與樣本
- [x] 3.3 實作 `parsers/syslog_parser.py`：解析 RFC5424 風格前綴
      （優先度、時間戳、主機名），從訊息內文抽取 `src_ip` /
      `dst_ip` / `dst_port` / `event_type`
- [x] 3.4 統一以 `parse(path, format) -> Iterator[NormalizedEvent]`
      作為三個 parser 的共同入口，供 CLI 呼叫

## 4. 滑動時間窗

- [x] 4.1 在 `lace/windowing.py` 實作依 `src_ip`（或
      `(src_ip, dst_ip)` 複合鍵，依規則需求而定）分組的
      `deque` 滑動窗口管理器
- [x] 4.2 實作依時間戳記從窗口左側淘汰過期事件的邏輯，確保窗口
      內事件時間跨度不超過設定的 `window_seconds`
- [x] 4.3 為窗口管理器撰寫單元測試，涵蓋「事件依序推入後正確淘汰」
      與「事件時間戳非遞增時的處理策略」

## 5. 偵測規則（Detectors）

- [x] 5.1 在 `detectors/base.py` 定義 `Detector` 介面
      （`detect(window, config) -> list[Finding]`）
- [x] 5.2 實作 `detectors/port_scan.py`：統計窗口內相異
      `dst_port` 數量，超過門檻產出 Finding
- [x] 5.3 實作 `detectors/brute_force.py`：統計窗口內
      `auth_failure` 次數，超過門檻產出 Finding；若窗口內隨後
      出現 `auth_success` 則提升 severity
- [x] 5.4 實作 `detectors/beaconing.py`：計算窗口內連續事件間隔的
      平均值與標準差，判斷變異係數是否低於門檻，並檢查最少樣本數
- [x] 5.5 實作 `detectors/exfil_volume.py`：累加窗口內
      `bytes_out`，超過門檻產出 Finding
- [x] 5.6 為四個 detector 各自撰寫至少「觸發」與「不觸發」兩種
      情境的單元測試，對應 spec.md 中的 Scenario

## 6. 信譽 / IOC 富化

- [x] 6.1 實作 `enrichment.py` 中的 `load_ioc_list(path) -> dict[str, list[str]]`
      （IP → tags 對照表），處理檔案不存在或格式錯誤時的清楚錯誤訊息
- [x] 6.2 實作 `enrich(finding, ioc_map) -> Finding`，為命中的
      Finding 附加 `reputation_tags`
- [x] 6.3 撰寫單元測試：命中清單、未命中清單、清單為空三種情境

## 7. 風險關聯（Correlation）

- [x] 7.1 在 `correlation.py` 實作依 `src_ip` 分組彙整所有
      Finding 的邏輯
- [x] 7.2 實作風險分數計算：不同規則權重加總（同規則多次觸發只
      計一次權重）、IOC 命中加成、結果封頂 100
- [x] 7.3 實作 `hit_count` 統計（每個規則被觸發的次數）與
      `first_seen` / `last_seen` 時間範圍計算
- [x] 7.4 撰寫單元測試：多規則合併、同規則去重計次、IOC 加成、
      分數封頂四種情境，對應 spec.md 中的 Scenario

## 8. 報表輸出

- [x] 8.1 實作 `reporters/json_reporter.py`：將 `Alert` 清單序列化
      為合法 JSON 檔案，空清單時輸出 `[]`
- [x] 8.2 實作 `reporters/table_reporter.py`：依 `risk_score` 由高
      到低排序，於終端機印出對齊的摘要表格；無 Alert 時印出
      「無異常事件」訊息
- [x] 8.3 撰寫單元測試驗證兩種輸出格式的正確性與邊界情況（空結果）

## 9. CLI 整合

- [x] 9.1 在 `cli.py` 用 `argparse` 實作 `lace run` 子命令，參數
      含 `--config`、`--input`（可多個）、`--format`、
      `--ioc-list`、`--output`
- [x] 9.2 串接完整流程：載入設定 → 解析 → 依規則跑滑動窗口偵測 →
      富化 → 關聯 → 輸出，並在設定驗證失敗時於解析前中止
- [x] 9.3 加入執行摘要輸出（處理事件數、parse error 數、耗時、
      Alert 數）

## 10. 端對端測試與文件

- [x] 10.1 建立 `tests/fixtures/` 下的合成測試資料，涵蓋能觸發
      每一種規則、也涵蓋不觸發的正常流量樣本
- [x] 10.2 撰寫 `tests/test_cli_end_to_end.py`：以 fixture 資料
      跑完整 CLI 流程，驗證輸出 JSON 內容與預期告警相符
- [x] 10.3 撰寫 `README.md`：安裝步驟、設定檔各欄位說明、CLI 使用
      範例、輸出格式範例（JSON schema 與表格截圖或範例文字）
- [x] 10.4 執行 `pytest` 全套測試，確認全數通過後於本 PR 描述中
      註明測試結果
