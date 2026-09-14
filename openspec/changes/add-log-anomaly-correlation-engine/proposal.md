# Proposal: 新增日誌異常關聯偵測引擎 (Log Anomaly Correlation Engine, LACE)

## Intent

目前批次匯入的防火牆 / Syslog 日誌只能靠人工在 SIEM 上下關鍵字查詢，缺乏一套
可重複執行、離線可跑的分析工具，能針對單一時間窗內的行為模式（掃描、暴力破解、
週期性回連、大量外送流量）自動偵測並產出結構化的告警，供資安人員後續在 SIEM
或 OpenCTI 中比對、開單。

本次改動要新增一個獨立的命令列工具 **LACE (Log Anomaly Correlation Engine)**，
以批次或串流方式讀取標準化後的日誌事件，執行多種偵測演算法，並將命中結果
關聯（correlate）成以來源 IP 為單位的風險分數，最終輸出機器可讀（JSON）與
人類可讀（表格 / CLI 摘要）的報表。

## Scope

**In scope:**

- 讀取三種輸入格式：RFC5424 風格 syslog 純文字、CSV（防火牆連線紀錄常見欄位）、
  JSON Lines（結構化事件）。
- 四種偵測演算法：連接埠掃描（port scan）、登入暴力破解（brute force）、
  週期性回連（beaconing）、單一時間窗內大量外送流量（exfiltration volume）。
- 本地 IOC / 信譽清單比對（CSV 格式的 IP 黑名單，含來源標籤）。
- 以來源 IP 為單位的多訊號風險分數聚合與去重（correlation）。
- YAML 設定檔驅動的門檻值、時間窗大小、輸入輸出路徑。
- JSON 告警輸出 + CLI 摘要表格輸出。
- 以合成測試資料（fixtures）驗證四種演算法與風險聚合邏輯的單元測試。

**Out of scope（本次不做，列為未來工作）：**

- 即時封包擷取（live packet capture）或網卡監聽。
- 分散式 / 多機串流處理（Kafka、Flink 等）。
- 任何機器學習模型或行為基線訓練，本次只做統計式規則偵測。
- 直接寫入 Graylog / OpenSearch（本次只產出檔案，日後可另開改動接上既有
  [[siem-stack]]）。
- Web UI 或儀表板呈現。

## Approach

以 Python 3.11+ 撰寫單一套件 `lace/`，核心設計是「每個來源 IP 一組滑動時間窗
狀態」，逐筆事件依時間序推進窗口、觸發偵測規則，並在處理結束後做一次跨規則的
風險聚合。設定（門檻值、視窗秒數、輸出路徑、IOC 清單路徑）全部外部化到 YAML，
不寫死在程式碼中，方便後續調校而不用改程式。

輸出分兩層：每條規則命中都先寫成獨立的 `Finding`，最後再由關聯引擎把同一來源
IP 的多個 `Finding` 合併成一個 `Alert`（含綜合風險分數與命中規則清單），避免
同一 IP 因為同時觸發掃描 + 暴力破解而在報表中出現兩筆不相關的紀錄。

詳細技術決策見 `design.md`；逐項可勾選的實作步驟見 `tasks.md`；行為契約（規則
與情境）見 `specs/log-anomaly-detection/spec.md`。
