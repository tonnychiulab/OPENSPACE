# LACE — Log Anomaly Correlation Engine

離線批次分析防火牆 / syslog 日誌：在每個來源 IP 的滑動時間窗內跑四種統計規則，
再把命中結果以來源 IP 聚合成風險分數。

## 安裝

需要 Python 3.11+。

```bash
pip install -e ".[dev]"
```

## 執行

```bash
lace run --config config.example.yaml --input logs.jsonl --format jsonl --output alerts.json
```

也支援 `--format csv` 與 `--format syslog`。`--input` 可給多個檔案。`--ioc-list` 可覆寫設定檔裡的 IOC 路徑。

設定驗證失敗時會在讀取任何日誌前以非零結束碼退出，並在 stderr 指出缺少或型別錯誤的欄位名稱。

結束時 stdout 會印出依 `risk_score` 排序的摘要表，以及 `processed_events` / `parse_errors` / `alerts` / `elapsed_s`。沒有告警時印出「無異常事件」，JSON 仍寫出 `[]`。

## 設定檔欄位

見 `config.example.yaml`。重點：

| 區塊 | 作用 |
| --- | --- |
| `port_scan.window_seconds` / `unique_dst_ports` | 同一 (src, dst) 在窗口內相異目的埠數 |
| `brute_force.window_seconds` / `failure_threshold` | `auth_failure` 次數；其後 `auth_success` 把 severity 升為 HIGH |
| `beaconing.window_seconds` / `cv_threshold` / `min_samples` | 連線間隔的變異係數 `pstdev / mean` |
| `exfil_volume.window_seconds` / `bytes_threshold_mb` | 來源 IP 的 `bytes_out` 加總 |
| `rule_weights` / `ioc_bonus` | 關聯分數：每種規則權重只加一次，IOC 命中再加成，上限 100 |
| `csv_columns` | CSV 欄名對應到內部事件欄位 |

## 輸出 JSON

```json
[
  {
    "src_ip": "203.0.113.9",
    "risk_score": 55,
    "triggered_rules": ["beaconing"],
    "hit_count": {"beaconing": 3},
    "reputation_tags": ["known_c2"],
    "first_seen": "2026-01-15T12:00:00",
    "last_seen": "2026-01-15T12:07:00"
  }
]
```

CLI 表格欄位：`src_ip`、`risk_score`、`triggered_rules`、`reputation_tags`。

## 測試

```bash
pytest
```
