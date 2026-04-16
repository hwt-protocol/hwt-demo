# hwt-demo

[HWT（Hash Web Token）協定](../hwt-protocol/)的開發伺服器與情境示例。

[正式文件](https://www.jimmont.com/hwt/hwt-demo) [議題](https://github.com/hwt-protocol/hwt-demo/issues)

HWT 是無狀態的跨網域授權 token 協定。任何網域皆為有效的 issuer（發行方）。任何能存取 issuer 公鑰的一方均可驗證 token — 無需中央提供者，各方之間無需預先設定。

## 示例

> 這些示例旨在促進使用 — 它們並非完整的參考資料或教條。它們在協定之上疊加了應用層假設（撤銷（revocation）、委派 API、伺服器慣例），這些假設有其用途但並非 HWT 規格書的一部分。有關協定實際保證的內容，請參閱 [SPEC.md](../hwt-protocol/SPEC.md)。有關共用詞彙，請參閱 [CONVENTIONS.md](../hwt-protocol/CONVENTIONS.md)。

### 情境示例

- [demo-agent-chain.js](demo-agent-chain.js)            AI 代理人委派鏈
- [demo-del-verify.js](demo-del-verify.js)             del[] 鏈路驗證與已撤銷連結偵測
- [demo-multiparty.js](demo-multiparty.js)             多方聯合授權
- [demo-federation.js](demo-federation.js)             自發性跨網域聯盟
- [demo-mesh.js](demo-mesh.js)                   服務網格委派鏈
- [demo-partner-api.js](demo-partner-api.js)            夥伴 API 存取與受眾綁定
- [demo-edge.js](demo-edge.js)                   邊緣的無狀態驗證
- [demo-revocation-strategies.js](demo-revocation-strategies.js)  短期 token 與明確撤銷 — 策略指南

### 部署基準

真實部署的起始點。請根據您的基礎設施進行調整。這些腳本不使用 `demo_hosts.js` 也不呼叫 `ensureServers()` — 它們是獨立的。

- [demo-hono-deno.js](demo-hono-deno.js)        Deno + Hono — 非對稱金鑰（Ed25519 / ECDSA）
- [demo-hono-cloudflare.js](demo-hono-cloudflare.js)  Cloudflare Workers + Hono — 非對稱金鑰
- [demo-hmac-deno.js](demo-hmac-deno.js)        Deno — HMAC，單一方，無基礎設施
- [demo-hmac-cloudflare.js](demo-hmac-cloudflare.js)  Cloudflare Workers — HMAC，共用密鑰

HMAC 適用於單一方部署（規格書 §2）。任何需要跨來源驗證或 delegation chain（委派鏈）的情境請使用非對稱基準。

## 需求

[Deno](https://deno.com/) — 無其他依賴。

## 快速開始 — 雙實例跨來源示例

```sh
# 終端 A — 認證伺服器
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json

# 終端 B — 第二服務
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8889 --hwt-keys=.hwt-keys-hostb.json
```

開啟 [http://localhost:8888](http://localhost:8888) 和 [http://localhost:8889](http://localhost:8889)。

**操作說明：** 在 A 上建立 token → 貼至 B 的「Verify External」。B 在執行時取得 A 的 JWKS 並驗證簽章，無需任何預先設定。

`--hwt-keys` 將金鑰對儲存至檔案，使 token 在伺服器重啟後仍有效。若僅需記憶體內金鑰，可省略此選項。

## 示例腳本

每個腳本針對運行中的伺服器實例執行完整情境。若伺服器尚未運行，`demo_hosts.js` 會自動啟動它們（連接埠 8888、8889、8880）：

```sh
deno run -A demo-agent-chain.js
deno run -A demo-del-verify.js
deno run -A demo-multiparty.js
deno run -A demo-federation.js
deno run -A demo-mesh.js
deno run -A demo-partner-api.js
deno run -A demo-edge.js
deno run -A demo-revocation-strategies.js
```

或先在各自的終端中手動啟動伺服器（請參閱上方快速開始），再執行任意示例腳本。

---

### [`demo-agent-chain.js`](demo-agent-chain.js) — AI 代理人委派鏈

使用者向認證伺服器進行身份驗證，並將授權委派給另一服務上的 AI 代理人。該代理人再委派給第三服務上的子代理人。最終 token 攜帶完整的密碼學溯源鏈（`del[]`），由外層 token 的簽章涵蓋 — 無需中央協調者即可防止篡改。每個連結均可獨立對照各自 issuer 公開的金鑰進行驗證。

流程涵蓋：根 token 建立 → 跨伺服器委派（hostB 上的 agent-1）→ 第二跳委派（hostA 上的 agent-2）→ 最終 token 的跨來源驗證 → 根 token 撤銷以展示應用層鏈路作廢。

---

### [`demo-del-verify.js`](demo-del-verify.js) — del[] 鏈路驗證

示範協定驗證與應用層撤銷查詢之間的區別 — 規格書 §12 明確區分的兩種不同結果。

在建立兩跳鏈（`user:alice → svc:agent-1 → svc:agent-2`）後，腳本撤銷 alice 的根 token 並展示關鍵時刻：協定驗證（`/api/verify-external`）仍通過 — 外層簽章有效，這是正確的。應用層鏈路驗證（`/api/verify-chain`）失敗 — alice 的 issuer 撤銷清單包含已撤銷的 `tid`。外層 token 未重新簽署；其簽章仍有效。只有應用層狀態查詢能偵測到作廢。

撤銷查詢是建立在 HWT 之上的程式庫功能。規格書 §13 明確將撤銷置於協定範圍之外。協定定義鏈路結構與簽章保證 — 如何運用由您自行決定。

---

### [`demo-multiparty.js`](demo-multiparty.js) — 多方聯合授權

兩個獨立組織各自向其自身 principal 發行核准者 token。協調服務針對每個 issuer 的 JWKS 跨來源驗證兩個 token — 無共享身份提供者，組織之間無需事先協議。只有當兩個 token 均驗證通過時，協調服務才使用嵌入兩位核准者身份的私有 authz schema（規格書 §4.2）發行聯合授權 token。任何下游服務均可驗證協調服務 token，並單憑 token 即可檢查法定人數記錄，無需重新聯繫原始 issuer。

示範為何 `del[]` 不適用於此情境：它是線性委派鏈，沒有多父節點形式。核准者身份是 `authz` 中的應用層資料，而非協定委派記錄。同時展示在某一方的 issuer 撤銷其根 token 不會傳播至協調服務的 token 儲存 — 每個 token 的狀態由其自身的 issuer 管理（規格書 §13）。

---

### [`demo-federation.js`](demo-federation.js) — 自發性跨網域聯盟

任意兩個 HWT issuer 只要雙方均發布符合規範的 well-known 端點，即可立即互通 — 無需註冊、無共享密鑰、無聯盟協議。此腳本雙向驗證 token：hostA 的 token 在 hostB 驗證，hostB 的 token 在 hostA 驗證。兩個主機互不充當對方的身份提供者；同一個規格書 §12 演算法在兩個方向上的執行完全相同。

同時示範來源元資料探索（`/.well-known/hwt.json`，規格書 §7）：文件內容、每個欄位的含義，以及 verifier（驗證方）在其缺失時的處理方式（套用文件化的欄位預設值並繼續 — 規格書 §7）。

---

### [`demo-mesh.js`](demo-mesh.js) — 服務網格委派鏈

跨三服務網格的服務間身份驗證，無需網格 CA、無需 mTLS、無需服務網格。來自認證服務（hostA）的使用者 token 流經閘道（hostB）和後端（hostC），每一跳均對照前一服務的 JWKS 進行驗證並重新委派。最終 token 為每個中間節點攜帶 `del[]` 條目 — 單憑 token 即可獨立驗證。

`authz` 在每一跳中均被明確追蹤：viewer → viewer → viewer。角色不變，因為規格書 §8.1 是規範性的 — 衍生 token 的 authz 必須等於或嚴格是主體 token 的 authz 之子集。在根節點撤銷會導致應用層鏈路崩潰。

---

### [`demo-partner-api.js`](demo-partner-api.js) — 夥伴 API 存取與受眾綁定

無共享憑證的 B2B API 整合。夥伴組織讀取使用端 API 的 `/.well-known/hwt.json` 以探索其需求，然後發行一個 `aud` 綁定至該特定 API、且 `authz` 陣列（規格書 §4.3）結合 RBAC schema 與 CONVENTIONS.md 管轄詞彙（`GDPR/2.0/DE`）的 token。使用端 API 跨來源驗證，然後在應用層強制執行受眾匹配（規格書 §12 第 9 步）。

`aud` 不匹配路徑被明確示範：一個密碼學上有效但綁定至不同服務的 token 在簽章驗證通過後於應用層被拒絕。這是混淆代理人防護措施（規格書 §11.4）。

同時涵蓋：`authz_evaluation: "all"` 要求兩個 schema 均滿足評估；以及 CONVENTIONS.md 的聲明：攜帶管轄聲明並非合規 — 它是結構性詞彙。

---

### [`demo-edge.js`](demo-edge.js) — 邊緣的無狀態驗證

同一個 token 在兩個節點（hostB、hostC）獨立驗證，在初始 JWKS 取得後不需往返 issuer（hostA）。

同時涵蓋：`kid` 未找到時的強制重新取得及其速率限制要求（規格書 §6、§11.7）；預先註冊與未知 issuer 的安全取捨（規格書 §11.1、§11.2、§A.7），以及為何預先註冊是建議的正式環境做法。

---

### [`demo-revocation-strategies.js`](demo-revocation-strategies.js) — 撤銷策略指南

採用者最常見的實務問題：何時應縮短 token 有效期，何時應建立撤銷系統？以實際 token 示範三種策略：

- **短期 token** — 一個 5 秒 token 在畫面上過期。零基礎設施。暴露時間窗等於 token 有效期。這是主要機制（規格書 §1）。
- **明確撤銷** — 一個 1 小時 token 在發行後數秒內被拒絕。即時作廢。基礎設施成本：驗證關鍵路徑上的撤銷端點。
- **混合式** — 一個 15 分鐘 token。正常情況使用自然過期。撤銷僅處理邊緣情況。大多數正式系統的實用預設選擇。

包含以部署情境為鍵的決策矩陣（金融 API、一般使用者 session、內部服務、長期代理人委派），使用規格書 §A.1 的有效期範圍，以及採用者在選擇策略前應回答的四個問題。將撤銷定位為合理有效期設定的補充，而非替代。

---

## 伺服器端點

`http.js` 是開發與示例伺服器。未針對正式環境進行強化。

### 協定端點（規格書定義）

| 方法 | 路徑 | 規格書 | 說明 |
|---|---|---|---|
| GET | `/.well-known/hwt-keys.json` | §6 | JWKS 公鑰 — 跨來源驗證的必要條件 |
| GET | `/.well-known/hwt.json` | §7 | Issuer 元資料 — authz schema、aud 政策、委派深度、端點宣告 |

### 程式庫擴充端點

這些端點實作疊加在協定之上的行為。撤銷與委派是應用層關注事項 — 規格書 §13 明確將其置於協定範圍之外。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/.well-known/hwt-revoked.json` | 撤銷清單 — 在 `hwt.json` 的 `endpoints.revocation` 下宣告 |
| POST | `/api/token/delegate` | 建立委派 token — 依規格書 §8.1 鏈路構建規則填充 `del[]` |
| POST | `/api/revoke` | 依 `tid` 或 token 字串撤銷 token |
| POST | `/api/revoke/clear` | 清除撤銷清單 — 開發便利功能 |

### 驗證端點

| 方法 | 路徑 | 協定 | 應用層 | 說明 |
|---|---|---|---|---|
| POST | `/api/verify` | ✓ 簽章 + 到期時間 | ✓ 本地撤銷 | 以本地金鑰驗證 + 查詢此伺服器的撤銷清單 |
| POST | `/api/verify-external` | ✓ 簽章 + 到期時間 | — | 依規格書 §12 跨來源取得 JWKS 並驗證 |
| POST | `/api/verify-chain` | ✓ 簽章 + 到期時間 | ✓ 完整 del[] 撤銷遍歷 | 驗證 + 取得每個 del[] 條目之 issuer 的撤銷清單 |
| POST | `/api/decode` | — | — | 解碼 payload — 不驗證簽章 |

**這些端點之間的區別至關重要。** `/api/verify-external` 執行規格書 §12 驗證演算法：簽章、到期時間、`del[]` 結構完整性（由外層簽章保證）。這是符合規範的 verifier 所實作的內容。`/api/verify-chain` 在此基礎上新增應用層狀態查詢 — 它取得每個 `del[]` 條目之 issuer 的撤銷清單，並確認無任何條目已被撤銷。若委派方的授權在 token 發行後已被撤銷，token 可通過協定驗證但無法通過鏈路驗證。請參閱 `demo-del-verify.js` 以逐步示範此區別。

### Token 與金鑰管理

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/api/token` | 建立已簽署的 token |
| GET | `/api/info` | 伺服器來源、kid、金鑰類型 |
| GET | `/api/keys` | 完整金鑰設定包括私鑰 — 僅限開發，切勿對外暴露 |
| POST | `/api/keys/generate` | 重新生成金鑰 |
| POST | `/api/keys/import` | 還原先前的金鑰設定 |

## 參數

### `http.js`

```
--port=8888          Port to listen on (default: 8888)
--hwt-keys=filename  Key file path for persistence across restarts
```

若不使用 `--hwt-keys`，金鑰在記憶體中生成，重啟後遺失。預設生成 Ed25519 金鑰。

## 相關資源

- [HWT 協定規格書](../hwt-protocol/)
- [hwtr-js 參考程式庫](../hwtr-js/)

## 授權條款

Apache License 2.0 — 請參閱 [LICENSE](./LICENSE.md)。
