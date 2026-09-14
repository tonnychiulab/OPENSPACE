# Delta for Log Anomaly Detection

## Purpose

定義 LACE 工具如何將原始日誌正規化、如何在每個來源 IP 的滑動時間窗內偵測
掃描 / 暴力破解 / 回連 / 大量外送等異常行為，以及如何把多個偵測結果關聯成
單一風險分數與報表輸出。

## ADDED Requirements

### Requirement: 多格式日誌正規化
系統 SHALL 將 syslog（RFC5424 風格純文字）、CSV（防火牆連線紀錄）、
JSON Lines 三種輸入格式都解析為統一的內部事件結構，至少包含
`timestamp`、`src_ip`、`dst_ip`、`dst_port`、`protocol`、`bytes_out`、
`event_type`（例如 `conn`、`auth_failure`、`auth_success`）欄位。

#### Scenario: 解析格式正確的 CSV 防火牆紀錄
- GIVEN 一個符合設定欄位對應（column mapping）的 CSV 檔案
- WHEN 執行 `lace run --input firewall.csv --format csv`
- THEN 每一列都被轉換為一筆 NormalizedEvent
- AND 事件數量與輸入檔案的資料列數相符（不含表頭）

#### Scenario: 遇到無法解析的單行不中斷整體處理
- GIVEN 一個 JSON Lines 檔案，其中有一行不是合法 JSON
- WHEN 執行解析
- THEN 該行被記錄為 parse error 並跳過
- AND 其餘合法行仍正常轉換為事件
- AND 執行結束後的摘要顯示被跳過的行數

### Requirement: 連接埠掃描偵測
系統 SHALL 在設定的時間窗內，偵測單一來源 IP 對單一目的 IP（或多個目的
IP）嘗試連線的相異目的埠數量是否超過設定門檻，並產出一筆 `port_scan`
Finding。

#### Scenario: 相異目的埠超過門檻觸發告警
- GIVEN 設定門檻為「60 秒內超過 15 個相異目的埠」
- WHEN 同一來源 IP 在 60 秒內對同一目的 IP 嘗試連線 20 個相異埠
- THEN 系統產出一筆 `port_scan` Finding，`severity` 為 MEDIUM 或以上
- AND Finding 的 `evidence` 記錄實際觸及的埠數與埠號清單

#### Scenario: 正常流量不誤判
- GIVEN 同樣的 60 秒門檻設定
- WHEN 同一來源 IP 在 60 秒內只連線 3 個相異目的埠
- THEN 系統不產出 `port_scan` Finding

### Requirement: 登入暴力破解偵測
系統 SHALL 偵測單一來源 IP 對單一帳號（或單一目的主機）在時間窗內累積的
`auth_failure` 事件數是否超過門檻，並在超過後緊接著出現 `auth_success`
時將 `severity` 提升為 HIGH（代表可能破解成功）。

#### Scenario: 連續失敗超過門檻觸發告警
- GIVEN 設定門檻為「5 分鐘內超過 10 次登入失敗」
- WHEN 同一來源 IP 在 5 分鐘內產生 12 次 `auth_failure` 事件
- THEN 系統產出一筆 `brute_force` Finding，`severity` 為 MEDIUM

#### Scenario: 失敗後緊接成功登入視為高風險
- GIVEN 上述已觸發的 `brute_force` Finding 情境
- WHEN 在同一時間窗結束前出現一筆該來源 IP 的 `auth_success` 事件
- THEN 該 Finding 的 `severity` 被更新為 HIGH
- AND `evidence` 註記「failure streak followed by success」

### Requirement: 週期性回連（Beaconing）偵測
系統 SHALL 針對單一來源 IP 到單一目的 IP 的連線事件，在視窗內事件數達到
最少樣本數門檻時，計算連續事件間隔的變異係數（標準差 / 平均值），當變異
係數低於設定門檻時判定為疑似 beaconing 並產出 Finding。

#### Scenario: 規律間隔的回連觸發告警
- GIVEN 設定「變異係數門檻 0.15，最少樣本數 6」
- WHEN 同一來源到同一目的 IP 在窗口內出現 8 次連線，間隔集中在 58–62 秒
- THEN 系統計算出變異係數低於 0.15
- AND 產出一筆 `beaconing` Finding，`evidence` 包含平均間隔與變異係數

#### Scenario: 樣本數不足不判定
- GIVEN 相同門檻設定
- WHEN 同一連線組合在窗口內只出現 3 次
- THEN 系統不產出 `beaconing` Finding（樣本數低於最少樣本數門檻）

#### Scenario: 間隔不規律不誤判
- GIVEN 相同門檻設定
- WHEN 同一連線組合出現 8 次，但間隔在 10 秒到 300 秒之間隨機分布
- THEN 計算出的變異係數高於 0.15
- AND 系統不產出 `beaconing` Finding

### Requirement: 大量外送流量偵測
系統 SHALL 在時間窗內累加單一來源 IP 的 `bytes_out` 總量，超過設定門檻
（可依 MB 為單位設定）時產出 `exfil_volume` Finding。

#### Scenario: 累積外送量超過門檻
- GIVEN 設定門檻為「10 分鐘內超過 500 MB 外送」
- WHEN 同一來源 IP 在 10 分鐘內的所有連線 `bytes_out` 加總達 620 MB
- THEN 系統產出一筆 `exfil_volume` Finding
- AND `evidence` 記錄總位元組數與涉及的相異目的 IP 數量

### Requirement: 本地 IOC / 信譽清單比對
系統 SHALL 支援載入 CSV 格式的本地 IOC 清單（欄位至少含 `ip`、
`tag`、`source`），並在產出 Finding 時，若該 Finding 的來源或目的 IP
命中清單，於 Finding 附加信譽標籤。

#### Scenario: 命中 IOC 清單的來源 IP 被標記
- GIVEN IOC 清單中含有一筆 `ip=203.0.113.9, tag=known_c2, source=internal_blocklist`
- WHEN 該 IP 觸發任一 Finding（例如 `beaconing`）
- THEN 該 Finding 附加 `reputation_tags: [known_c2]`

#### Scenario: 未命中清單不影響 Finding 產出
- GIVEN 同樣的 IOC 清單
- WHEN 一個不在清單中的 IP 觸發 Finding
- THEN Finding 正常產出，`reputation_tags` 為空陣列

### Requirement: 跨規則風險關聯與去重
系統 SHALL 將同一來源 IP 在整個分析期間內產生的所有 Finding 聚合為一筆
Alert，計算綜合 `risk_score`（0–100，依觸發規則種類加權，命中 IOC 清單
加成），並記錄每種規則的觸發次數，避免同一來源 IP 因規則重複觸發而在報表
中產生多筆互不相關的紀錄。

#### Scenario: 單一來源 IP 觸發多種規則合併為一筆 Alert
- GIVEN 同一來源 IP 在分析期間先觸發 `port_scan`、後觸發 `brute_force`
- WHEN 執行關聯聚合
- THEN 輸出中該來源 IP 只出現一筆 Alert
- AND Alert 的 `triggered_rules` 包含 `port_scan` 與 `brute_force`
- AND `risk_score` 等於兩個規則權重之和（未超過 100 的情況下）

#### Scenario: 同一規則重複觸發只計一次權重但記錄次數
- GIVEN 同一來源 IP 的 `port_scan` 規則在分析期間觸發 3 次
- WHEN 執行關聯聚合
- THEN 該 Alert 的 `risk_score` 只計入 `port_scan` 權重一次
- AND `hit_count.port_scan` 等於 3

#### Scenario: 命中 IOC 清單的來源 IP 風險分數獲得加成
- GIVEN 同一來源 IP 觸發至少一個 Finding 且命中 IOC 清單
- WHEN 執行關聯聚合
- THEN 該 Alert 的 `risk_score` 額外加上設定檔中定義的 `ioc_bonus`
- AND 加總後的分數不超過 100（封頂）

### Requirement: 設定檔驅動與啟動時驗證
系統 MUST 從外部 YAML 設定檔讀取所有門檻值、時間窗大小、規則權重、輸入
輸出路徑與 IOC 清單路徑，並在程式啟動時驗證設定檔完整性與型別，發現問題
時 SHALL 在執行任何解析前終止並輸出清楚的錯誤訊息（指出哪個欄位有問題）。

#### Scenario: 設定檔缺少必要欄位時 fail-fast
- GIVEN 一份 YAML 設定檔缺少 `port_scan.window_seconds` 欄位
- WHEN 執行 `lace run --config config.yaml ...`
- THEN 程式在讀取任何日誌前就以非零結束碼結束
- AND 錯誤訊息明確指出缺少的欄位名稱

#### Scenario: 合法設定檔正常載入
- GIVEN 一份包含所有必要欄位且型別正確的 YAML 設定檔
- WHEN 程式啟動
- THEN 設定被成功載入為內部設定物件
- AND 後續各 detector 使用該設定物件中的門檻值運作

### Requirement: 報表輸出
系統 SHALL 將最終的 Alert 清單輸出為 JSON 檔案（供程式化後續處理），並在
CLI 執行結束時印出人類可讀的摘要表格（依 `risk_score` 由高到低排序，至少
包含來源 IP、風險分數、觸發規則清單、信譽標籤）。

#### Scenario: JSON 輸出包含完整欄位
- GIVEN 分析結束後產生至少一筆 Alert
- WHEN 系統寫出 `--output alerts.json`
- THEN 該檔案是合法 JSON
- AND 每筆 Alert 物件都包含 `src_ip`、`risk_score`、`triggered_rules`、
  `hit_count`、`reputation_tags`、`first_seen`、`last_seen`

#### Scenario: 無任何 Alert 時仍正常輸出空結果
- GIVEN 輸入日誌中沒有任何事件觸發規則
- WHEN 分析完成
- THEN JSON 輸出為空陣列 `[]`（而非缺少檔案或報錯）
- AND CLI 摘要印出「無異常事件」訊息而非空白或例外堆疊
