# hwt-demo

Entwicklungsserver und Szenario-Demos für das [HWT (Hash Web Token)-Protokoll](../hwt-protocol/).

[Offizielle Dokumentation](https://hwtprotocol.com/hwt-demo) [Issues](https://github.com/hwt-protocol/hwt-demo/issues)

HWT ist ein zustandsloses, domänenübergreifendes Autorisierungs-Token-Protokoll. Jede Domain ist ein gültiger Issuer (Aussteller). Tokens sind von jedem verifizierbar, der die öffentlichen Schlüssel des Issuers erreichen kann – kein zentraler Anbieter, keine Vorkonfiguration zwischen den Parteien.

## Demos

> Diese Demos erleichtern den Einstieg – sie sind keine vollständigen Referenzen und kein Dogma. Sie legen Anwendungsannahmen über dem Protokoll ab (Revocation (Widerruf), Delegierungs-APIs, Server-Konventionen), die nützlich, aber nicht Teil der HWT-Spezifikation sind. Was das Protokoll tatsächlich garantiert, entnehmen Sie [SPEC.md](../hwt-protocol/SPEC.md). Gemeinsames Vokabular finden Sie in [CONVENTIONS.md](../hwt-protocol/CONVENTIONS.md).

### Szenario-Demos

- [demo-agent-chain.js](demo-agent-chain.js)            KI-Agenten-Delegation Chain (Delegierungskette)
- [demo-del-verify.js](demo-del-verify.js)             del[]-Kettenverifizierung und Erkennung widerrufener Links
- [demo-multiparty.js](demo-multiparty.js)             Gemeinsame Autorisierung mehrerer Parteien
- [demo-federation.js](demo-federation.js)             Spontane domänenübergreifende Föderation
- [demo-mesh.js](demo-mesh.js)                   Service-Mesh-Delegation Chain
- [demo-partner-api.js](demo-partner-api.js)            Partner-API-Zugriff und Audience-Bindung
- [demo-edge.js](demo-edge.js)                   Zustandslose Verifizierung am Edge
- [demo-revocation-strategies.js](demo-revocation-strategies.js)  Kurzlebige Tokens vs. explizite Revocation – Strategieleitfaden

### Deployment-Baselines

Ausgangspunkte für reale Deployments. Passen Sie diese an Ihre Infrastruktur an. Diese Skripte verwenden kein `demo_hosts.js` und rufen kein `ensureServers()` auf – sie sind eigenständig.

- [demo-hono-deno.js](demo-hono-deno.js)        Deno + Hono – asymmetrische Schlüssel (Ed25519 / ECDSA)
- [demo-hono-cloudflare.js](demo-hono-cloudflare.js)  Cloudflare Workers + Hono – asymmetrische Schlüssel
- [demo-hmac-deno.js](demo-hmac-deno.js)        Deno – HMAC, Single-Party, keine Infrastruktur
- [demo-hmac-cloudflare.js](demo-hmac-cloudflare.js)  Cloudflare Workers – HMAC, gemeinsames Geheimnis

HMAC ist für Single-Party-Deployments (Spec §2). Verwenden Sie die asymmetrischen Baselines für alles, was eine ursprungsübergreifende Verifizierung oder Delegation Chains erfordert.

## Voraussetzungen

[Deno](https://deno.com/) – keine weiteren Abhängigkeiten.

## Schnellstart – Demo mit zwei Instanzen und Cross-Origin

```sh
# Terminal A – Auth-Server
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json

# Terminal B – zweiter Service
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8889 --hwt-keys=.hwt-keys-hostb.json
```

Öffnen Sie [http://localhost:8888](http://localhost:8888) und [http://localhost:8889](http://localhost:8889).

**Was zu tun ist:** Erstellen Sie einen Token auf A → fügen Sie ihn in „Verify External" auf B ein. B ruft zur Laufzeit A's JWKS ab und verifiziert die Signatur ohne vorherige Konfiguration.

`--hwt-keys` speichert Ihr Schlüsselpaar in einer Datei, damit Tokens Server-Neustarts überleben. Lassen Sie diesen Parameter weg für reine In-Memory-Schlüssel.

## Demo-Skripte

Jedes Skript führt ein vollständiges Szenario gegen laufende Serverinstanzen aus. `demo_hosts.js` startet diese automatisch, falls sie noch nicht laufen (Ports 8888, 8889, 8880):

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

Oder starten Sie die Server zuerst manuell in separaten Terminals (siehe Schnellstart oben) und führen Sie dann beliebige Demo-Skripte aus.

---

### [`demo-agent-chain.js`](demo-agent-chain.js) – KI-Agenten-Delegation Chain

Ein Benutzer authentifiziert sich bei einem Auth-Server und delegiert Befugnisse an einen KI-Agenten auf einem separaten Service. Dieser Agent delegiert an einen Unteragenten auf einem dritten Service. Der finale Token trägt die vollständige kryptografische Herkunftskette (`del[]`), abgedeckt durch die Signatur des äußeren Tokens – manipulationssicher ohne zentralen Koordinator. Jedes Glied ist unabhängig anhand der veröffentlichten Schlüssel des jeweiligen Issuers verifizierbar.

Demonstriert: Erstellung des Root-Tokens → serverübergreifende Delegation (agent-1 auf hostB) → zweite Delegation (agent-2 auf hostA) → Cross-Origin-Verifizierung des finalen Tokens → Root-Token-Revocation mit anschließender Invalidierung der Kette auf Anwendungsebene.

---

### [`demo-del-verify.js`](demo-del-verify.js) – del[]-Kettenverifizierung

Zeigt den Unterschied zwischen Protokollverifizierung und Revocation-Prüfung auf Anwendungsebene – zwei unterschiedliche Ergebnisse, die Spec §12 explizit trennt.

Nach dem Aufbau einer Zwei-Hop-Kette (`user:alice → svc:agent-1 → svc:agent-2`) widerruft das Skript Alices Root-Token und zeigt den entscheidenden Moment: Die Protokollverifizierung (`/api/verify-external`) besteht weiterhin – die äußere Signatur ist gültig, was korrekt ist. Die Kettenverifizierung auf Anwendungsebene (`/api/verify-chain`) schlägt fehl – die Revocation-Liste des Issuers von Alice enthält die widerrufene `tid`. Der äußere Token wurde nicht neu signiert; seine Signatur bleibt gültig. Nur die Zustandsprüfung auf Anwendungsebene erkennt die Invalidierung.

Revocation-Prüfung ist eine Bibliotheksfunktion, die auf HWT aufbaut. Spec §13 stellt Revocation explizit außerhalb des Protokollgeltungsbereichs. Das Protokoll definiert Kettenstruktur und Signaturgarantie – was Sie damit machen, entscheiden Sie selbst.

---

### [`demo-multiparty.js`](demo-multiparty.js) – Gemeinsame Autorisierung mehrerer Parteien

Zwei unabhängige Organisationen stellen jeweils Genehmigungstoken für ihre eigenen Principals aus. Ein Koordinationsdienst verifiziert beide Tokens Cross-Origin gegen den JWKS des jeweiligen Issuers – kein gemeinsamer Identity-Provider, keine vorherige Vereinbarung zwischen den Organisationen. Erst wenn beide Tokens verifiziert sind, stellt der Koordinator einen gemeinsamen Autorisierungstoken mit einem privaten authz-Schema (Spec §4.2) aus, der beide Genehmiger-Identitäten enthält. Jeder nachgelagerte Dienst kann den Koordinationstoken verifizieren und den Quorum-Eintrag allein aus dem Token heraus prüfen, ohne die ursprünglichen Issuer erneut zu kontaktieren.

Zeigt, warum `del[]` hier nicht anwendbar ist: Es handelt sich um eine lineare Delegation Chain ohne Mehrfach-Eltern-Form. Die Genehmiger-Identitäten sind Anwendungsdaten in `authz`, keine Protokoll-Delegierungseinträge. Zeigt außerdem, dass der Widerruf des Root-Tokens einer Partei bei ihrem Issuer nicht in den Token-Store des Koordinators propagiert – jeder Token wird bei seinem eigenen Issuer verwaltet (Spec §13).

---

### [`demo-federation.js`](demo-federation.js) – Spontane domänenübergreifende Föderation

Zwei beliebige HWT-Issuer interoperieren, sobald beide konforme well-known-Endpunkte veröffentlichen – keine Registrierung, keine gemeinsamen Geheimnisse, keine Föderationsvereinbarung. Dieses Skript verifiziert Tokens in beide Richtungen: hostA-Token wird bei hostB verifiziert, hostB-Token bei hostA. Keiner der Hosts ist Identity-Provider des anderen; derselbe Spec-§12-Algorithmus läuft in beiden Richtungen identisch.

Zeigt außerdem die Origin-Metadaten-Discovery (`/.well-known/hwt.json`, Spec §7): was das Dokument enthält, was jedes Feld bedeutet und was Verifier (Prüfer) tun, wenn es fehlt (dokumentierte Standardfeldwerte anwenden und fortfahren – Spec §7).

---

### [`demo-mesh.js`](demo-mesh.js) – Service-Mesh-Delegation Chain

Service-zu-Service-Authentifizierung über ein Drei-Service-Mesh ohne Mesh-CA, ohne mTLS und ohne Service-Mesh. Ein Benutzer-Token vom Auth-Service (hostA) fließt über ein Gateway (hostB) und ein Backend (hostC); jeder Hop wird gegen den JWKS des vorherigen Service verifiziert und neu delegiert. Der finale Token trägt `del[]`-Einträge für jeden Zwischenschritt – unabhängig allein aus dem Token heraus verifizierbar.

`authz` wird über jeden Hop explizit nachverfolgt: viewer → viewer → viewer. Die Rolle ändert sich nicht, da Spec §8.1 normativ ist – die authz des abgeleiteten Tokens muss gleich oder eine echte Teilmenge der authz des Subject-Tokens sein. Revocation am Root-Token kollabiert die Kette auf der Anwendungsebene.

---

### [`demo-partner-api.js`](demo-partner-api.js) – Partner-API-Zugriff und Audience-Bindung

B2B-API-Integration ohne gemeinsame Credentials. Eine Partnerorganisation liest die `/.well-known/hwt.json` der konsumierenden API, um deren Anforderungen zu ermitteln, und stellt dann einen Token mit `aud`-Bindung an diese spezifische API und einem Array-`authz` (Spec §4.3) aus, das ein RBAC-Schema mit CONVENTIONS.md-Jurisdiktionsvokabular (`GDPR/2.0/DE`) kombiniert. Die konsumierende API verifiziert Cross-Origin und erzwingt anschließend Audience-Matching auf Anwendungsebene (Spec §12, Schritt 9).

Der `aud`-Mismatch-Pfad wird explizit demonstriert: Ein kryptografisch gültiger Token, der an einen anderen Service gebunden ist, wird auf Anwendungsebene nach bestandener Signaturverifizierung abgelehnt. Dies ist die Absicherung gegen den Confused-Deputy-Angriff (Spec §11.4).

Behandelt außerdem: `authz_evaluation: "all"`, bei dem beide Schemata die Auswertung erfüllen müssen; und den CONVENTIONS.md-Hinweis, dass das Mitführen eines Jurisdiktionsanspruchs keine Compliance darstellt – es ist strukturelles Vokabular.

---

### [`demo-edge.js`](demo-edge.js) – Zustandslose Verifizierung am Edge

Derselbe Token wird unabhängig an zwei Knoten (hostB, hostC) verifiziert, ohne weitere Verbindungen zum Issuer (hostA) nach dem initialen JWKS-Abruf.

Behandelt außerdem: den erzwungenen Neu-Abruf bei nicht gefundener `kid` und dessen Rate-Limit-Anforderung (Spec §6, §11.7); den Sicherheits-Tradeoff zwischen vorab registrierten und unbekannten Issuern (Spec §11.1, §11.2, §A.7) und warum Vorab-Registrierung die empfohlene Produktionskonfiguration ist.

---

### [`demo-revocation-strategies.js`](demo-revocation-strategies.js) – Revocation-Strategieleitfaden

Die häufigste praktische Frage für Adopter: Wann verkürzt man die Token-Lebensdauer, und wann baut man ein Revocation-System? Drei Strategien werden mit echten Tokens demonstriert:

- **Kurzlebige Tokens** – ein 5-Sekunden-Token läuft auf dem Bildschirm ab. Keine Infrastruktur. Exposition entspricht der Token-Lebensdauer. Dies ist der primäre Mechanismus (Spec §1).
- **Explizite Revocation** – ein 1-Stunden-Token wird innerhalb von Sekunden nach der Ausstellung abgelehnt. Sofortige Invalidierung. Infrastrukturkosten: Revocation-Endpunkt auf dem Verifizierungspfad.
- **Hybrid** – ein 15-Minuten-Token. Im Normalfall wird das natürliche Ablaufen genutzt. Revocation behandelt nur Ausnahmefälle. Der praktische Standard für die meisten Produktivsysteme.

Enthält eine Entscheidungsmatrix nach Deployment-Kontext (Finanz-API, allgemeine Benutzersession, interner Service, langlebige Agenten-Delegation) mit Lebensdauerbereichen aus Spec §A.1 sowie vier Fragen, die ein Adopter vor der Strategiewahl beantworten sollte. Stellt Revocation als Ergänzung zu einer gut gewählten Lebensdauer dar, nicht als Ersatz dafür.

---

## Server-Endpunkte

[`http.js`](http.js) ist ein Entwicklungs- und Demonstrationsserver. Er ist nicht für den Produktionseinsatz gehärtet.

### Protokoll-Endpunkte (spezifikationsdefiniert)

| Methode | Pfad | Spec | Beschreibung |
|---|---|---|---|
| GET | `/.well-known/hwt-keys.json` | §6 | Öffentliche JWKS-Schlüssel – für Cross-Origin-Verifizierung erforderlich |
| GET | `/.well-known/hwt.json` | §7 | Issuer-Metadaten – authz-Schemata, aud-Richtlinie, Delegationstiefe, Endpunktdeklarationen |

### Endpunkte der Bibliothekserweiterung

Diese Endpunkte implementieren Verhalten, das über das Protokoll hinausgeht. Revocation und Delegation sind Anwendungsbelange – Spec §13 stellt sie explizit außerhalb des Protokollgeltungsbereichs.

| Methode | Pfad | Beschreibung |
|---|---|---|
| GET | `/.well-known/hwt-revoked.json` | Revocation-Liste – deklariert in `hwt.json` unter `endpoints.revocation` |
| POST | `/api/token/delegate` | Delegierten Token erstellen – befüllt `del[]` gemäß den Kettenaufbauregeln in Spec §8.1 |
| POST | `/api/revoke` | Token anhand von `tid` oder Token-String widerrufen |
| POST | `/api/revoke/clear` | Revocation-Liste leeren – Entwickler-Hilfsfunktion |

### Verifizierungsendpunkte

| Methode | Pfad | Protokoll | Anwendungsebene | Beschreibung |
|---|---|---|---|---|
| POST | `/api/verify` | ✓ Sig + Ablaufzeit | ✓ lokale Revocation | Gegen lokale Schlüssel verifizieren + Revocation-Liste dieses Servers prüfen |
| POST | `/api/verify-external` | ✓ Sig + Ablaufzeit | — | Cross-Origin-JWKS-Abruf und Verifizierung gemäß Spec §12 |
| POST | `/api/verify-chain` | ✓ Sig + Ablaufzeit | ✓ vollständige del[]-Revocation-Prüfung | Verifizieren + Revocation-Liste des Issuers für jeden del[]-Eintrag abrufen |
| POST | `/api/decode` | — | — | payload dekodieren – keine Signaturprüfung |

**Die Unterscheidung zwischen diesen Endpunkten ist wichtig.** `/api/verify-external` führt den Verifizierungsalgorithmus aus Spec §12 aus: Signatur, Ablaufzeit, strukturelle Integrität von `del[]` (durch die äußere Signatur garantiert). Dies ist das, was ein konformer Verifier implementiert. `/api/verify-chain` fügt darüber hinaus eine Zustandsprüfung auf Anwendungsebene hinzu – es ruft die Revocation-Liste des Issuers für jeden `del[]`-Eintrag ab und bestätigt, dass keiner widerrufen wurde. Ein Token kann die Protokollverifizierung bestehen und die Kettenverifizierung nicht bestehen, wenn die Berechtigung eines Delegators seit der Token-Ausstellung widerrufen wurde. Siehe `demo-del-verify.js` für eine schrittweise Demonstration dieses Unterschieds.

### Token- und Schlüsselverwaltung

| Methode | Pfad | Beschreibung |
|---|---|---|
| POST | `/api/token` | Signierten Token erstellen |
| GET | `/api/info` | Server-Origin, kid, Schlüsseltyp |
| GET | `/api/keys` | Vollständige Schlüsselkonfiguration einschließlich Private Key – nur für Entwicklung, niemals exponieren |
| POST | `/api/keys/generate` | Schlüssel neu generieren |
| POST | `/api/keys/import` | Frühere Schlüsselkonfiguration wiederherstellen |

## Argumente

### `http.js`

```
--port=8888          Port to listen on (default: 8888)
--hwt-keys=filename  Key file path for persistence across restarts
```

Ohne `--hwt-keys` werden Schlüssel im Speicher generiert und bei Neustart verworfen. Standardmäßig werden Ed25519-Schlüssel generiert.

## Verwandte Ressourcen

- [HWT-Protokollspezifikation](../hwt-protocol)
- [hwtr-js-Referenzbibliothek](../hwtr-js)

## Lizenz

Apache License 2.0 – siehe [LICENSE](./LICENSE).

