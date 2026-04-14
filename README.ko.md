# hwt-demo

[HWT(Hash Web Token) 프로토콜](../hwt-protocol/)의 개발 서버 및 시나리오 데모입니다.

[공식 문서](https://www.jimmont.com/hwt/hwt-demo) [이슈](https://github.com/hwt-protocol/hwt-demo/issues)

HWT는 상태 비저장, 도메인 간 인가 token 프로토콜입니다. 어느 도메인이든 유효한 발급자(issuer)가 될 수 있습니다. Token은 발급자의 공개 키에 접근할 수 있는 누구나 검증할 수 있으며 — 중앙 공급자도, 당사자 간 사전 설정도 불필요합니다.

## 데모

> 이 데모들은 활용을 돕기 위한 것으로, 완전한 참조 또는 교범이 아닙니다. 유용하지만 HWT 스펙의 일부가 아닌 애플리케이션 가정(폐기, 위임 API, 서버 규약)을 프로토콜 위에 덧붙입니다. 프로토콜이 실제로 보장하는 것에 대해서는 [SPEC.md](../hwt-protocol/SPEC.md)를, 공유 어휘에 대해서는 [CONVENTIONS.md](../hwt-protocol/CONVENTIONS.md)를 참조하세요.

### 시나리오 데모

- [demo-agent-chain.js](demo-agent-chain.js)            AI 에이전트 위임 체인
- [demo-del-verify.js](demo-del-verify.js)             del[] 체인 검증 및 폐기된 링크 감지
- [demo-multiparty.js](demo-multiparty.js)             다자간 공동 인가
- [demo-federation.js](demo-federation.js)             자발적 도메인 간 연합
- [demo-mesh.js](demo-mesh.js)                   서비스 메시 위임 체인
- [demo-partner-api.js](demo-partner-api.js)            파트너 API 접근 및 오디언스 바인딩
- [demo-edge.js](demo-edge.js)                   엣지에서의 상태 비저장 검증
- [demo-revocation-strategies.js](demo-revocation-strategies.js)  단수명 token 대 명시적 폐기(revocation) — 전략 가이드

### 배포 기준점

실제 배포를 위한 시작점입니다. 인프라에 맞게 조정하세요. 이 스크립트들은 `demo_hosts.js`를 사용하지 않으며 `ensureServers()`를 호출하지 않습니다 — 독립적으로 동작합니다.

- [demo-hono-deno.js](demo-hono-deno.js)        Deno + Hono — 비대칭 키(Ed25519 / ECDSA)
- [demo-hono-cloudflare.js](demo-hono-cloudflare.js)  Cloudflare Workers + Hono — 비대칭 키
- [demo-hmac-deno.js](demo-hmac-deno.js)        Deno — HMAC, 단일 당사자, 인프라 불필요
- [demo-hmac-cloudflare.js](demo-hmac-cloudflare.js)  Cloudflare Workers — HMAC, 공유 시크릿

HMAC은 단일 당사자 배포(스펙 §2)용입니다. 크로스 오리진 검증이나 위임 체인이 필요한 경우 비대칭 기준점을 사용하세요.

## 요구 사항

[Deno](https://deno.com/) — 다른 의존성 없음.

## 빠른 시작 — 두 인스턴스 도메인 간 데모

```sh
# 터미널 A — 인증 서버
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json

# 터미널 B — 두 번째 서비스
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8889 --hwt-keys=.hwt-keys-hostb.json
```

[http://localhost:8888](http://localhost:8888)과 [http://localhost:8889](http://localhost:8889)를 여세요.

**해볼 것:** A에서 token 생성 → B의 "외부 검증"에 붙여넣기. B가 런타임에 A의 JWKS를 가져와 사전 설정 없이 서명을 검증합니다.

`--hwt-keys`는 서버 재시작 후에도 token이 유효하도록 키 쌍을 파일에 저장합니다. 생략하면 메모리 전용 키를 사용합니다.

## 데모 스크립트

각 스크립트는 라이브 서버 인스턴스에서 완전한 시나리오를 실행합니다. `demo_hosts.js`는 서버가 아직 실행 중이지 않은 경우 자동으로 시작합니다(포트 8888, 8889, 8880):

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

또는 별도의 터미널에서 서버를 먼저 수동으로 시작한 후(위 빠른 시작 참조) 데모 스크립트를 실행하세요.

---

### [`demo-agent-chain.js`](demo-agent-chain.js) — AI 에이전트 위임 체인

사용자가 인증 서버에 인증하고 별도 서비스의 AI 에이전트에게 권한을 위임합니다. 해당 에이전트는 세 번째 서비스의 하위 에이전트에게 위임합니다. 최종 token은 전체 암호화 출처 체인(`del[]`)을 담고 있으며, 이는 외부 token의 서명으로 보호됩니다 — 중앙 코디네이터 없이 변조 방지됩니다. 각 링크는 해당 발급자의 공개 키에 대해 독립적으로 검증 가능합니다.

다음을 단계별로 안내합니다: 루트 token 생성 → 크로스 서버 위임(hostB의 agent-1) → 2단계 위임(hostA의 agent-2) → 최종 token의 크로스 오리진 검증 → 루트 token 폐기 시 애플리케이션 계층 체인 무효화.

---

### [`demo-del-verify.js`](demo-del-verify.js) — del[] 체인 검증

프로토콜 검증과 애플리케이션 계층 폐기 확인의 차이를 보여줍니다 — 스펙 §12가 명시적으로 구분하는 두 가지 결과입니다.

`user:alice → svc:agent-1 → svc:agent-2`의 2단계 체인을 구성한 후 alice의 루트 token을 폐기하고 결정적인 순간을 보여줍니다: 프로토콜 검증(`/api/verify-external`)은 여전히 통과합니다 — 외부 서명이 유효하며, 이는 올바른 동작입니다. 애플리케이션 계층 체인 검증(`/api/verify-chain`)은 실패합니다 — alice의 발급자 폐기 목록에 폐기된 `tid`가 포함되어 있습니다. 외부 token은 재서명되지 않았으며, 서명은 여전히 유효합니다. 오직 애플리케이션 계층 상태 확인만이 무효화를 감지합니다.

폐기 확인은 HWT 위에 구축된 라이브러리 기능입니다. 스펙 §13은 폐기를 프로토콜 범위 밖으로 명시합니다. 프로토콜은 체인 구조와 서명 보장을 정의하며 — 그 활용 방법은 여러분이 결정합니다.

---

### [`demo-multiparty.js`](demo-multiparty.js) — 다자간 공동 인가

두 독립 조직이 각자의 주체에게 승인자 token을 발급합니다. 코디네이터 서비스는 공유 신원 공급자도, 조직 간 사전 합의도 없이 각 발급자의 JWKS에 대해 두 token을 크로스 오리진으로 검증합니다. 양쪽이 모두 검증될 때만 코디네이터가 비공개 authz 스키마(스펙 §4.2)를 사용해 두 승인자 신원을 포함하는 공동 인가 token을 발급합니다. 하위 서비스는 원래 발급자에게 재연락하지 않고 token만으로 코디네이터 token을 검증하고 쿼럼 기록을 검사할 수 있습니다.

`del[]`이 여기 적용되지 않는 이유를 설명합니다: 다중 부모 형식이 없는 선형 위임 체인이기 때문입니다. 승인자 신원은 프로토콜 위임 레코드가 아닌 `authz`의 애플리케이션 데이터입니다. 한 당사자의 루트 token을 발급자에서 폐기해도 코디네이터의 token 저장소에는 전파되지 않음을 보여줍니다 — 각 token의 상태는 자체 발급자에서 관리됩니다(스펙 §13).

---

### [`demo-federation.js`](demo-federation.js) — 자발적 도메인 간 연합

두 HWT 발급자가 적합한 well-known 엔드포인트를 공개하는 순간 등록, 공유 시크릿, 연합 합의 없이 즉시 상호 운용됩니다. 이 스크립트는 양방향으로 token을 검증합니다: hostA token을 hostB에서 검증, hostB token을 hostA에서 검증. 어느 호스트도 상대방의 신원 공급자가 아니며, 동일한 스펙 §12 알고리즘이 양방향 모두에서 동일하게 실행됩니다.

오리진 메타데이터 발견(`/.well-known/hwt.json`, 스펙 §7)도 보여줍니다: 문서에 무엇이 있는지, 각 필드가 무엇을 의미하는지, 문서가 없을 때 검증자가 무엇을 하는지(기본 필드 값을 적용하고 계속 진행 — 스펙 §7).

---

### [`demo-mesh.js`](demo-mesh.js) — 서비스 메시 위임 체인

메시 CA, mTLS, 서비스 메시 없이 3개 서비스에 걸친 서비스 간 인증. 인증 서비스(hostA)의 사용자 token이 게이트웨이(hostB)와 백엔드(hostC)를 거치며, 각 단계에서 이전 서비스의 JWKS에 대해 검증되고 재위임됩니다. 최종 token은 모든 중간 단계에 대한 `del[]` 항목을 담고 있어 token만으로 독립적으로 검증 가능합니다.

`authz`는 모든 단계에서 명시적으로 추적됩니다: viewer → viewer → viewer. 역할이 변경되지 않는 이유는 스펙 §8.1이 규범적이기 때문입니다 — 파생 token의 authz는 주체 token의 authz와 동등하거나 그 엄격한 부분집합이어야 합니다. 루트에서의 폐기는 애플리케이션 계층에서 체인을 붕괴시킵니다.

---

### [`demo-partner-api.js`](demo-partner-api.js) — 파트너 API 접근 및 오디언스 바인딩

공유 자격증명 없는 B2B API 연동. 파트너 조직이 소비 API의 `/.well-known/hwt.json`을 읽어 요구 사항을 파악한 후, 해당 특정 API에 바인딩된 `aud`와 RBAC 스키마 및 CONVENTIONS.md 관할권 어휘(`GDPR/2.0/DE`)를 결합한 배열 `authz`(스펙 §4.3)로 token을 발급합니다. 소비 API는 크로스 오리진으로 검증한 후 애플리케이션 계층에서 오디언스 일치를 강제합니다(스펙 §12 9단계).

`aud` 불일치 경로를 명시적으로 보여줍니다: 다른 서비스에 바인딩된 암호학적으로 유효한 token은 서명 검증 통과 후 애플리케이션 계층에서 거부됩니다. 이것이 confused deputy 완화입니다(스펙 §11.4).

또한 다음을 다룹니다: 두 스키마 모두를 평가에서 충족하도록 요구하는 `authz_evaluation: "all"`; 관할권 클레임을 담는 것이 규정 준수가 아니라 구조적 어휘라는 CONVENTIONS.md의 고지 사항.

---

### [`demo-edge.js`](demo-edge.js) — 엣지에서의 상태 비저장 검증

최초 JWKS 페치 후 발급자(hostA)에 대한 왕복 없이 두 노드(hostB, hostC)에서 동일한 token을 독립적으로 검증합니다.

또한 다음을 다룹니다: kid를 찾지 못했을 때 강제 재페치 및 속도 제한 요구 사항(스펙 §6, §11.7); 사전 등록 대 미지의 발급자 보안 트레이드오프(스펙 §11.1, §11.2, §A.7), 사전 등록이 권장되는 프로덕션 방식인 이유.

---

### [`demo-revocation-strategies.js`](demo-revocation-strategies.js) — 폐기 전략 가이드

도입자에게 가장 흔한 실용적 질문: token 유효 기간을 줄일지 폐기 시스템을 구축할지. 세 가지 전략을 라이브 token으로 보여줍니다:

- **단수명 token** — 5초짜리 token이 화면에서 만료됩니다. 인프라 불필요. 노출 기간이 token 유효 기간과 같습니다. 이것이 기본 메커니즘입니다(스펙 §1).
- **명시적 폐기** — 1시간짜리 token이 발급 후 수 초 내에 거부됩니다. 즉각적인 무효화. 인프라 비용: 검증 중요 경로에 폐기 엔드포인트 필요.
- **하이브리드** — 15분짜리 token. 일반적인 경우 자연 만료를 사용합니다. 폐기는 예외적인 경우에만 처리합니다. 대부분의 프로덕션 시스템의 실용적 기본값.

스펙 §A.1의 유효 기간 범위를 사용한 배포 컨텍스트(금융 API, 일반 사용자 세션, 내부 서비스, 장기 에이전트 위임)별 의사결정 매트릭스와, 도입자가 전략 선택 전에 답해야 할 네 가지 질문을 포함합니다. 폐기를 잘 선택된 유효 기간의 보완재로 제시하며, 대체재가 아님을 명확히 합니다.

---

## 서버 엔드포인트

[`http.js`](http.js)는 개발 및 시연용 서버입니다. 프로덕션 강화는 되어 있지 않습니다.

### 프로토콜 엔드포인트 (스펙 정의)

| 메서드 | 경로 | 스펙 | 설명 |
|---|---|---|---|
| GET | `/.well-known/hwt-keys.json` | §6 | JWKS 공개 키 — 크로스 오리진 검증에 필요 |
| GET | `/.well-known/hwt.json` | §7 | 발급자 메타데이터 — authz 스키마, aud 정책, 위임 깊이, 엔드포인트 선언 |

### 라이브러리 확장 엔드포인트

이 엔드포인트들은 프로토콜 위에 계층화된 동작을 구현합니다. 폐기와 위임은 애플리케이션 관심사입니다 — 스펙 §13은 이를 명시적으로 프로토콜 범위 밖으로 분류합니다.

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/.well-known/hwt-revoked.json` | 폐기 목록 — `hwt.json`의 `endpoints.revocation` 아래에 선언됨 |
| POST | `/api/token/delegate` | 위임된 token 생성 — 스펙 §8.1 체인 구성 규칙에 따라 `del[]` 채움 |
| POST | `/api/revoke` | `tid` 또는 token 문자열로 token 폐기 |
| POST | `/api/revoke/clear` | 폐기 목록 초기화 — 개발 편의용 |

### 검증 엔드포인트

| 메서드 | 경로 | 프로토콜 | 애플리케이션 계층 | 설명 |
|---|---|---|---|---|
| POST | `/api/verify` | ✓ 서명 + 만료 | ✓ 로컬 폐기 | 로컬 키 검증 + 이 서버의 폐기 목록 확인 |
| POST | `/api/verify-external` | ✓ 서명 + 만료 | — | 크로스 오리진 JWKS 페치 및 스펙 §12에 따른 검증 |
| POST | `/api/verify-chain` | ✓ 서명 + 만료 | ✓ 전체 del[] 폐기 순회 | 검증 + 각 del[] 항목의 발급자 폐기 목록 페치 |
| POST | `/api/decode` | — | — | payload 디코딩 — 서명 확인 없음 |

**이 엔드포인트들 간의 차이가 중요합니다.** `/api/verify-external`은 스펙 §12 검증 알고리즘을 실행합니다: 서명, 만료, `del[]` 구조적 무결성(외부 서명으로 보장됨). 이것이 적합한 검증자가 구현하는 것입니다. `/api/verify-chain`은 그 위에 애플리케이션 계층 상태 확인을 추가합니다 — 각 `del[]` 항목의 발급자 폐기 목록을 페치하고 폐기된 것이 없는지 확인합니다. Token이 프로토콜 검증을 통과하고도 체인 검증에 실패할 수 있습니다. 위임자의 인가가 token 발급 이후 폐기된 경우입니다. 이 구분의 단계별 시연은 `demo-del-verify.js`를 참조하세요.

### Token 및 키 관리

| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/api/token` | 서명된 token 생성 |
| GET | `/api/info` | 서버 오리진, kid, 키 유형 |
| GET | `/api/keys` | 개인 키를 포함한 전체 키 구성 — 개발 전용, 절대 노출하지 말 것 |
| POST | `/api/keys/generate` | 키 재생성 |
| POST | `/api/keys/import` | 이전 키 구성 복원 |

## 인수

### `http.js`

```
--port=8888          수신 포트 (기본값: 8888)
--hwt-keys=filename  재시작 후 지속성을 위한 키 파일 경로
```

`--hwt-keys` 없이 실행하면 키가 메모리에 생성되고 재시작 시 소실됩니다. 기본적으로 Ed25519 키가 생성됩니다.

## 관련 자료

- [HWT 프로토콜 명세](../hwt-protocol/)
- [hwtr-js 참조 라이브러리](../hwtr-js/)

## 라이선스

Apache License 2.0 — [LICENSE](./LICENSE) 참조.

