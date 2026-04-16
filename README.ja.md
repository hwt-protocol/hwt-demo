# hwt-demo

[HWT（Hash Web Token）プロトコル](../hwt-protocol/)の開発サーバーとシナリオデモ。

[正規ドキュメント](https://www.jimmont.com/hwt/hwt-demo) [issues](https://github.com/hwt-protocol/hwt-demo/issues)

HWTはステートレスなクロスドメイン認可トークンプロトコルである。任意のドメインが有効なissuer（発行者）となれる。トークンはissuerの公開鍵に到達できる誰でも検証可能であり、中央プロバイダーも当事者間の事前設定も不要だ。

## デモ

> これらのデモは利用を促進するためのものであり、包括的なリファレンスや教義ではない。プロトコルの上に、便利だがHWT仕様の一部ではないアプリケーション側の前提（revocation（失効）、委任API、サーバー規約）を重ねている。プロトコルが実際に保証する内容については、[SPEC.md](../hwt-protocol/SPEC.md)を参照。共通の語彙についてはCONVENTIONS.mdを参照。

### シナリオデモ

- [demo-agent-chain.js](demo-agent-chain.js)            AIエージェントのdelegation chain（委任チェーン）
- [demo-del-verify.js](demo-del-verify.js)             del[]チェーン検証と失効リンク検出
- [demo-multiparty.js](demo-multiparty.js)             マルチパーティ共同認可
- [demo-federation.js](demo-federation.js)             自発的なクロスドメインフェデレーション
- [demo-mesh.js](demo-mesh.js)                   サービスメッシュのdelegation chain
- [demo-partner-api.js](demo-partner-api.js)            パートナーAPIアクセスとaudience binding
- [demo-edge.js](demo-edge.js)                   エッジでのステートレス検証
- [demo-revocation-strategies.js](demo-revocation-strategies.js)  短命トークンと明示的なrevocationの比較 — 戦略ガイド

### デプロイメントベースライン

実際のデプロイメントの出発点。自分のインフラに合わせて調整すること。これらのスクリプトは`demo_hosts.js`を使用せず`ensureServers()`も呼び出さない — スタンドアロンで動作する。

- [demo-hono-deno.js](demo-hono-deno.js)        Deno + Hono — 非対称鍵（Ed25519 / ECDSA）
- [demo-hono-cloudflare.js](demo-hono-cloudflare.js)  Cloudflare Workers + Hono — 非対称鍵
- [demo-hmac-deno.js](demo-hmac-deno.js)        Deno — HMAC、単一パーティ、インフラ不要
- [demo-hmac-cloudflare.js](demo-hmac-cloudflare.js)  Cloudflare Workers — HMAC、共有シークレット

HMACは単一パーティのデプロイメント（spec §2）向け。クロスオリジン検証やdelegation chainが必要な場合は非対称鍵のベースラインを使用すること。

## 必要環境

[Deno](https://deno.com/) — 他の依存関係なし。

## クイックスタート — 2インスタンスのクロスオリジンデモ

```sh
# ターミナルA — 認証サーバー
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json

# ターミナルB — 第2サービス
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8889 --hwt-keys=.hwt-keys-hostb.json
```

[http://localhost:8888](http://localhost:8888) と [http://localhost:8889](http://localhost:8889) を開く。

**操作手順：** Aでトークンを作成 → Bの「Verify External」に貼り付ける。Bはランタイムにentry AのJWKSを取得し、事前設定なしで署名を検証する。

`--hwt-keys`は鍵ペアをファイルに保存し、サーバー再起動後もトークンが有効に保たれる。インメモリ限定の鍵を使う場合は省略する。

## デモスクリプト

各スクリプトはライブのサーバーインスタンスに対して完全なシナリオを実行する。`demo_hosts.js`はサーバーが起動していない場合に自動的に起動する（ポート8888、8889、8880）：

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

または先に別ターミナルでサーバーを手動起動し（上記クイックスタート参照）、その後デモスクリプトを実行する。

---

### [`demo-agent-chain.js`](demo-agent-chain.js) — AIエージェントのdelegation chain

ユーザーが認証サーバーで認証し、別サービス上のAIエージェントに権限を委任する。そのエージェントは第三のサービス上のサブエージェントにさらに委任する。最終トークンは完全な暗号的プロベナンスチェーン（`del[]`）を保持し、外側トークンの署名によってカバーされる — 中央コーディネーターなしで改ざん防止を実現する。各リンクはそれぞれのissuerの公開鍵に対して独立に検証可能である。

ウォークスルー内容：ルートトークン生成 → クロスサーバー委任（hostB上のagent-1） → 第2ホップ委任（hostA上のagent-2） → 最終トークンのクロスオリジン検証 → ルートトークンのrevocationによるアプリケーション層でのチェーン無効化の確認。

---

### [`demo-del-verify.js`](demo-del-verify.js) — del[]チェーン検証

プロトコル検証とアプリケーション層のrevocation確認の違いを示す — spec §12が明示的に区別する2つの異なる結果。

2ホップチェーン（`user:alice → svc:agent-1 → svc:agent-2`）を構築した後、aliceのルートトークンを失効させ、重要な瞬間を示す：プロトコル検証（`/api/verify-external`）は依然として成功する — 外側の署名は有効であり、これは正しい動作である。アプリケーション層のチェーン検証（`/api/verify-chain`）は失敗する — aliceのissuerのrevocationリストに失効した`tid`が含まれているためだ。外側トークンは再署名されていないため、その署名は有効なままである。無効化を検出できるのはアプリケーション層の状態確認のみである。

revocation確認はHWTの上に構築されたライブラリ機能である。Spec §13はrevocationを明示的にプロトコルスコープ外に置いている。プロトコルはチェーン構造と署名保証を定義する — それをどう活用するかは実装者が決定する。

---

### [`demo-multiparty.js`](demo-multiparty.js) — マルチパーティ共同認可

2つの独立した組織がそれぞれ自組織のプリンシパルにapproverトークンを発行する。コーディネーターサービスは両トークンを各issuerのJWKSに対してクロスオリジンで検証する — 共有アイデンティティプロバイダーも組織間の事前合意も不要だ。両方の検証が成功した場合にのみ、コーディネーターは両承認者のアイデンティティを埋め込んだプライベートauthzスキーマ（spec §4.2）を使用して共同認可トークンを発行する。下流のサービスはコーディネータートークンを検証し、元のissuerに再接続せずにトークンのみからクォーラム記録を検査できる。

ここで`del[]`が適用されない理由を示す：`del[]`はマルチペアレント形式を持たない線形なdelegation chainである。承認者のアイデンティティは`authz`内のアプリケーションデータであり、プロトコルの委任記録ではない。また、一方のルートトークンをissuerで失効させても、コーディネーターのトークンストアには伝播しないことも示す — 各トークンの状態はそれぞれのissuerで管理される（spec §13）。

---

### [`demo-federation.js`](demo-federation.js) — 自発的なクロスドメインフェデレーション

2つのHWT issuerは、双方が準拠したwell-knownエンドポイントを公開した時点で即座に相互運用可能になる — 登録も共有シークレットもフェデレーション協定も不要だ。このスクリプトは両方向でトークンを検証する：hostAのトークンをhostBで検証し、hostBのトークンをhostAで検証する。どちらのホストも相手のアイデンティティプロバイダーではなく、同じspec §12アルゴリズムが両方向で同一に実行される。

オリジンメタデータのdiscovery（`/.well-known/hwt.json`、spec §7）も示す：ドキュメントに含まれる内容、各フィールドの意味、ドキュメントが存在しない場合にverifierが行うこと（記載されたフィールドのデフォルト値を適用して継続 — spec §7）。

---

### [`demo-mesh.js`](demo-mesh.js) — サービスメッシュのdelegation chain

メッシュCA、mTLS、サービスメッシュなしで3サービスメッシュを横断するサービス間認証。認証サービス（hostA）からのユーザートークンがゲートウェイ（hostB）とバックエンド（hostC）を経由し、各ホップで前のサービスのJWKSに対して検証され再委任される。最終トークンはすべての中間ノードの`del[]`エントリを保持し、トークン単体から独立に検証可能である。

`authz`は各ホップを通じて明示的に追跡される：viewer → viewer → viewer。ロールが変わらないのはspec §8.1が規範的であるためだ — 派生トークンのauthzは対象トークンのauthzと同等か、その厳格なサブセットでなければならない。ルートでのrevocationはアプリケーション層でチェーンを崩壊させる。

---

### [`demo-partner-api.js`](demo-partner-api.js) — パートナーAPIアクセスとaudience binding

共有credentialなしのB2B APIインテグレーション。パートナー組織は利用側APIの`/.well-known/hwt.json`を読み込んで要件を確認し、その特定のAPIにバインドされた`aud`と、RBACスキーマとCONVENTIONS.mdの管轄語彙（`GDPR/2.0/DE`）を組み合わせた配列`authz`（spec §4.3）を持つトークンを発行する。利用側APIはクロスオリジンで検証し、アプリケーション層でaudience matchingを強制する（spec §12 step 9）。

`aud`のミスマッチパスを明示的に示す：別サービスにバインドされた暗号的に有効なトークンが、署名検証通過後にアプリケーション層で拒否される。これはconfused deputy（仲介者の混乱）対策である（spec §11.4）。

合わせて示す内容：両方のスキーマが評価を満たすことを要求する`authz_evaluation: "all"`；管轄クレームを保持することはコンプライアンスではなく構造的な語彙に過ぎないというCONVENTIONS.mdの注意書き。

---

### [`demo-edge.js`](demo-edge.js) — エッジでのステートレス検証

初回JWKS取得後、issuer（hostA）へのラウンドトリップなしで、同一トークンを2つのノード（hostB、hostC）で独立に検証する。

合わせて示す内容：`kid`未検出時の強制再取得とそのレート制限要件（spec §6、§11.7）；事前登録済みissuerと未知issuerのセキュリティトレードオフ（spec §11.1、§11.2、§A.7）、および事前登録が推奨される本番環境構成である理由。

---

### [`demo-revocation-strategies.js`](demo-revocation-strategies.js) — revocation戦略ガイド

採用者からの最も一般的な実践的な質問：トークンのライフタイムを短縮するのはいつで、revocationシステムを構築するのはいつか？3つの戦略をライブトークンで示す：

- **短命トークン** — 5秒トークンが画面上で失効する。インフラコストなし。露出ウィンドウはトークンライフタイムと等しい。これが主要なメカニズムである（spec §1）。
- **明示的なrevocation** — 1時間トークンが発行から数秒で拒否される。即時無効化。インフラコスト：revocationエンドポイントが検証クリティカルパス上に必要。
- **ハイブリッド** — 15分トークン。通常ケースは自然な期限切れを使用。revocationはエッジケースのみを処理する。ほとんどの本番システムにとって実用的なデフォルト。

デプロイメントコンテキスト（金融API、一般ユーザーセッション、内部サービス、長命なエージェント委任）をキーとした意思決定マトリックスを含み、spec §A.1のライフタイム範囲を使用する。採用者が戦略を選択する前に答えるべき4つの質問も含む。revocationを適切に選択されたライフタイムの代替ではなく補完として位置づける。

---

## サーバーエンドポイント

[`http.js`](http.js)は開発およびデモ用サーバーである。本番環境向けに堅牢化されていない。

### プロトコルエンドポイント（仕様定義）

| メソッド | パス | Spec | 説明 |
|---|---|---|---|
| GET | `/.well-known/hwt-keys.json` | §6 | JWKS公開鍵 — クロスオリジン検証に必要 |
| GET | `/.well-known/hwt.json` | §7 | issuerメタデータ — authzスキーマ、audポリシー、委任深度、エンドポイント宣言 |

### ライブラリ拡張エンドポイント

これらのエンドポイントはプロトコルの上に重ねられた動作を実装する。revocationと委任はアプリケーション上の問題であり、spec §13はこれらを明示的にプロトコルスコープ外に置いている。

| メソッド | パス | 説明 |
|---|---|---|
| GET | `/.well-known/hwt-revoked.json` | revocationリスト — `hwt.json`の`endpoints.revocation`で宣言 |
| POST | `/api/token/delegate` | 委任トークンを生成 — spec §8.1のチェーン構築ルールに従い`del[]`を設定 |
| POST | `/api/revoke` | `tid`またはトークン文字列でトークンを失効 |
| POST | `/api/revoke/clear` | revocationリストをクリア — 開発用便宜機能 |

### 検証エンドポイント

| メソッド | パス | プロトコル | アプリケーション層 | 説明 |
|---|---|---|---|---|
| POST | `/api/verify` | ✓ 署名 + 有効期限 | ✓ ローカルrevocation | ローカル鍵で検証 + このサーバーのrevocationリストを確認 |
| POST | `/api/verify-external` | ✓ 署名 + 有効期限 | — | spec §12に従いクロスオリジンJWKSを取得して検証 |
| POST | `/api/verify-chain` | ✓ 署名 + 有効期限 | ✓ del[]全体のrevocation確認 | 検証 + 各`del[]`エントリのissuerのrevocationリストを取得 |
| POST | `/api/decode` | — | — | payloadをデコード — 署名確認なし |

**これらのエンドポイントの違いは重要である。** `/api/verify-external`はspec §12の検証アルゴリズムを実行する：署名、有効期限、`del[]`の構造的整合性（外側の署名によって保証）。これが準拠したverifierが実装するものである。`/api/verify-chain`はその上にアプリケーション層の状態確認を追加する — 各`del[]`エントリのissuerのrevocationリストを取得し、失効していないことを確認する。トークン発行後に委任者の認可が失効した場合、トークンはプロトコル検証を通過してもチェーン検証で失敗する可能性がある。この違いのステップバイステップのデモについては`demo-del-verify.js`を参照。

### トークンと鍵の管理

| メソッド | パス | 説明 |
|---|---|---|
| POST | `/api/token` | 署名済みトークンを生成 |
| GET | `/api/info` | サーバーオリジン、kid、鍵タイプ |
| GET | `/api/keys` | 秘密鍵を含む完全な鍵設定 — 開発専用、絶対に公開しないこと |
| POST | `/api/keys/generate` | 鍵を再生成 |
| POST | `/api/keys/import` | 以前の鍵設定を復元 |

## 引数

### `http.js`

```
--port=8888          リスニングポート（デフォルト：8888）
--hwt-keys=filename  再起動をまたいで永続化するための鍵ファイルパス
```

`--hwt-keys`なしの場合、鍵はメモリ内に生成され再起動時に消失する。デフォルトではEd25519鍵が生成される。

## 関連

- [HWTプロトコル仕様](../hwt-protocol/)
- [hwtr-jsリファレンスライブラリ](../hwtr-js/)

## ライセンス

Apache License 2.0 — [LICENSE](./LICENSE.md)を参照。

---

