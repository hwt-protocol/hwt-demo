# hwt-demo

Servidor de desarrollo y demostraciones de escenarios para el [protocolo HWT (Hash Web Token)](../hwt-protocol/).

[documentación canónica](https://www.jimmont.com/hwt/hwt-demo) [issues](https://github.com/hwt-protocol/hwt-demo/issues)

HWT es un protocolo de token de autorización sin estado y entre dominios. Cualquier dominio es un issuer (emisor) válido. Los tokens son verificables por cualquier parte que pueda acceder a las claves públicas del issuer — sin proveedor central, sin preconfiguración entre las partes.

## Demostraciones

> Estas demostraciones facilitan el uso — no son referencias exhaustivas ni dogma. Agregan suposiciones de la aplicación sobre el protocolo (revocation (revocación), APIs de delegación, convenciones de servidor) que son útiles pero no forman parte de la especificación de HWT. Para lo que el protocolo garantiza de forma normativa, consulta [SPEC.md](../hwt-protocol/SPEC.md). Para el vocabulario compartido, consulta [CONVENTIONS.md](../hwt-protocol/CONVENTIONS.md).

### Demostraciones de escenarios

- [demo-agent-chain.js](demo-agent-chain.js)            Cadena de delegación de agentes de IA
- [demo-del-verify.js](demo-del-verify.js)              Verificación de cadena del[] y detección de enlaces revocados
- [demo-multiparty.js](demo-multiparty.js)              Autorización conjunta entre múltiples partes
- [demo-federation.js](demo-federation.js)              Federación espontánea entre dominios
- [demo-mesh.js](demo-mesh.js)                          Cadena de delegación en malla de servicios
- [demo-partner-api.js](demo-partner-api.js)            Acceso a API de socios y vinculación de audiencia
- [demo-edge.js](demo-edge.js)                          Verificación sin estado en el borde (edge)
- [demo-revocation-strategies.js](demo-revocation-strategies.js)  Tokens de corta duración vs revocation explícita — guía de estrategias

### Bases de despliegue

Puntos de partida para despliegues reales. Adáptalos a tu infraestructura. Estos scripts no usan `demo_hosts.js` y no llaman a `ensureServers()` — son independientes.

- [demo-hono-deno.js](demo-hono-deno.js)        Deno + Hono — claves asimétricas (Ed25519 / ECDSA)
- [demo-hono-cloudflare.js](demo-hono-cloudflare.js)  Cloudflare Workers + Hono — claves asimétricas
- [demo-hmac-deno.js](demo-hmac-deno.js)        Deno — HMAC, un solo servicio, sin infraestructura
- [demo-hmac-cloudflare.js](demo-hmac-cloudflare.js)  Cloudflare Workers — HMAC, secreto compartido

HMAC es para despliegues de un solo servicio (especificación §2). Usa las bases asimétricas para cualquier caso que requiera verificación entre orígenes o delegation chains (cadenas de delegación).

## Requisitos

[Deno](https://deno.com/) — sin otras dependencias.

## Inicio rápido — demostración entre dos instancias de distintos orígenes

```sh
# Terminal A — servidor de autenticación
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json

# Terminal B — segundo servicio
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8889 --hwt-keys=.hwt-keys-hostb.json
```

Abre [http://localhost:8888](http://localhost:8888) y [http://localhost:8889](http://localhost:8889).

**Qué hacer:** Crea un token en A → pégalo en "Verify External" en B. B obtiene el JWKS de A en tiempo de ejecución y verifica la firma sin ninguna configuración previa.

`--hwt-keys` guarda tu par de claves en un archivo para que los tokens sobrevivan a reinicios del servidor. Omítelo si solo quieres claves en memoria.

## Scripts de demostración

Cada script ejecuta un escenario completo contra instancias de servidor en vivo. `demo_hosts.js` las inicia automáticamente si no están ya en ejecución (puertos 8888, 8889, 8880):

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

O inicia los servidores manualmente en terminales separadas primero (ver el inicio rápido anterior) y luego ejecuta cualquier script de demostración.

---

### [`demo-agent-chain.js`](demo-agent-chain.js) — Cadena de delegación de agentes de IA

Un usuario se autentica con un servidor de autenticación y delega autoridad a un agente de IA en un servicio separado. Ese agente delega a un subagente en un tercer servicio. El token final lleva la cadena completa de procedencia criptográfica (`del[]`), cubierta por la firma del token externo — a prueba de manipulaciones sin necesidad de un coordinador central. Cada enlace es verificable de forma independiente contra las claves publicadas por el issuer correspondiente.

Recorre: creación del token raíz → delegación entre servidores (agent-1 en hostB) → segunda delegación (agent-2 en hostA) → verificación entre orígenes del token final → revocación del token raíz mostrando la invalidación de la cadena en la capa de aplicación.

---

### [`demo-del-verify.js`](demo-del-verify.js) — Verificación de cadena del[]

Demuestra la distinción entre la verificación del protocolo y la comprobación de revocation en la capa de aplicación — dos resultados distintos que la especificación §12 separa explícitamente.

Tras construir una cadena de dos saltos (`user:alice → svc:agent-1 → svc:agent-2`), el script revoca el token raíz de alice y muestra el momento crítico: la verificación del protocolo (`/api/verify-external`) sigue siendo exitosa — la firma externa es válida, lo cual es correcto. La verificación de cadena en la capa de aplicación (`/api/verify-chain`) falla — la lista de revocation del issuer de alice contiene el `tid` revocado. El token externo no fue refirmado; su firma sigue siendo válida. Solo la comprobación de estado en la capa de aplicación detecta la invalidación.

La comprobación de revocation es una función de la biblioteca construida sobre HWT. La especificación §13 sitúa explícitamente la revocation fuera del alcance del protocolo. El protocolo define la estructura de la cadena y la garantía de firma — lo que hagas con ello es tu decisión.

---

### [`demo-multiparty.js`](demo-multiparty.js) — Autorización conjunta entre múltiples partes

Dos organizaciones independientes emiten tokens de aprobación a sus propios principales. Un servicio coordinador verifica ambos tokens entre orígenes contra el JWKS de cada issuer — sin proveedor de identidad compartido, sin acuerdo previo entre las organizaciones. Solo cuando ambos se verifican, el coordinador emite un token de autorización conjunta usando un esquema authz privado (especificación §4.2) que incorpora las identidades de ambos aprobadores. Cualquier servicio posterior puede verificar el token del coordinador e inspeccionar el registro de quórum desde el propio token, sin volver a contactar a los issuers originales.

Demuestra por qué `del[]` no aplica aquí: es una cadena de delegación lineal sin forma multi-padre. Las identidades de los aprobadores son datos de aplicación en `authz`, no registros de delegación del protocolo. También muestra que revocar el token raíz de una parte en su issuer no se propaga al almacén de tokens del coordinador — el estado de cada token se gestiona en su propio issuer (especificación §13).

---

### [`demo-federation.js`](demo-federation.js) — Federación espontánea entre dominios

Dos issuers de HWT interoperan en el momento en que ambos publican endpoints well-known conformes — sin registro previo, sin secretos compartidos, sin acuerdo de federación. Este script verifica tokens en ambas direcciones: token de hostA verificado en hostB, token de hostB verificado en hostA. Ningún host actúa como proveedor de identidad del otro; el mismo algoritmo de la especificación §12 se ejecuta de forma idéntica en ambas direcciones.

También demuestra el descubrimiento de metadatos del origen (`/.well-known/hwt.json`, especificación §7): qué contiene el documento, qué significa cada campo, y qué hacen los verifiers (verificadores) cuando está ausente (aplican los valores predeterminados documentados del campo y continúan — especificación §7).

---

### [`demo-mesh.js`](demo-mesh.js) — Cadena de delegación en malla de servicios

Autenticación de servicio a servicio a través de una malla de tres servicios sin una CA de malla, sin mTLS y sin una malla de servicios. Un token de usuario del servicio de autenticación (hostA) fluye a través de una pasarela (hostB) y un backend (hostC); cada salto se verifica contra el JWKS del servicio anterior y se redelegarelega. El token final lleva entradas `del[]` para cada intermediario — verificables de forma independiente desde el propio token.

`authz` se rastrea explícitamente en cada salto: viewer → viewer → viewer. El rol no cambia porque la especificación §8.1 es normativa — el authz del token derivado debe ser igual o un subconjunto estricto del authz del token de origen. La revocación en la raíz colapsa la cadena en la capa de aplicación.

---

### [`demo-partner-api.js`](demo-partner-api.js) — Acceso a API de socios y vinculación de audiencia

Integración de API B2B sin credenciales compartidas. Una organización socia lee el `/.well-known/hwt.json` de la API consumidora para descubrir sus requisitos, luego emite un token con `aud` vinculado a esa API específica y `authz` en array (especificación §4.3) que combina un esquema RBAC con el vocabulario de jurisdicción de CONVENTIONS.md (`GDPR/2.0/DE`). La API consumidora verifica entre orígenes y luego aplica la correspondencia de audiencia en la capa de aplicación (especificación §12 paso 9).

El caso de coincidencia incorrecta de `aud` se demuestra explícitamente: un token criptográficamente válido vinculado a un servicio diferente es rechazado en la capa de aplicación tras pasar la verificación de firma. Esta es la mitigación del problema del ayudante confundido (especificación §11.4).

También cubre: `authz_evaluation: "all"` que requiere que ambos esquemas satisfagan la evaluación; y el aviso de CONVENTIONS.md de que llevar una declaración de jurisdicción no es cumplimiento normativo — es vocabulario estructural.

---

### [`demo-edge.js`](demo-edge.js) — Verificación sin estado en el borde (edge)

El mismo token verificado de forma independiente en dos nodos (hostB, hostC) sin ningún viaje de ida al issuer (hostA) después de la obtención inicial del JWKS.

También cubre: la obtención forzada por `kid` no encontrado y su requisito de límite de tasa (especificación §6, §11.7); la compensación de seguridad entre issuer pre-registrado vs issuer desconocido (especificación §11.1, §11.2, §A.7) y por qué el pre-registro es la postura de producción recomendada.

---

### [`demo-revocation-strategies.js`](demo-revocation-strategies.js) — Guía de estrategias de revocación

La pregunta práctica más común para quienes adoptan el protocolo: ¿cuándo acortar la vida útil del token frente a construir un sistema de revocation? Se demuestran tres estrategias con tokens en vivo:

- **Tokens de corta duración** — un token de 5 segundos expira en pantalla. Sin infraestructura. La ventana de exposición es igual a la vida útil del token. Este es el mecanismo principal (especificación §1).
- **Revocation explícita** — un token de 1 hora es rechazado en segundos después de la emisión. Invalidación inmediata. Costo de infraestructura: endpoint de revocation en la ruta crítica de verificación.
- **Híbrido** — un token de 15 minutos. El caso normal usa expiración natural. La revocation maneja solo los casos límite. El valor predeterminado práctico para la mayoría de los sistemas en producción.

Incluye una matriz de decisión organizada por contexto de despliegue (API financiera, sesión de usuario general, servicio interno, delegación de agente de larga duración) usando rangos de vida útil de la especificación §A.1, y cuatro preguntas que quien adopte el protocolo debe responder antes de elegir una estrategia. Enmarca la revocation como un complemento a una vida útil bien elegida, no como sustituto de ella.

---

## Endpoints del servidor

[`http.js`](http.js) es un servidor de desarrollo y demostración. No está reforzado para producción.

### Endpoints del protocolo (definidos en la especificación)

| Método | Ruta | Especificación | Descripción |
|---|---|---|---|
| GET | `/.well-known/hwt-keys.json` | §6 | Claves públicas JWKS — requeridas para verificación entre orígenes |
| GET | `/.well-known/hwt.json` | §7 | Metadatos del issuer — esquemas authz, política aud, profundidad de delegación, declaraciones de endpoints |

### Endpoints de extensión de la biblioteca

Estos endpoints implementan comportamiento construido sobre el protocolo. La revocation y la delegación son responsabilidades de la aplicación — la especificación §13 las sitúa explícitamente fuera del alcance del protocolo.

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/.well-known/hwt-revoked.json` | Lista de revocation — declarada en `hwt.json` bajo `endpoints.revocation` |
| POST | `/api/token/delegate` | Crear un token delegado — llena `del[]` según las reglas de construcción de cadena de la especificación §8.1 |
| POST | `/api/revoke` | Revocar un token por `tid` o por cadena de token |
| POST | `/api/revoke/clear` | Limpiar la lista de revocation — conveniencia para desarrollo |

### Endpoints de verificación

| Método | Ruta | Protocolo | Capa de aplicación | Descripción |
|---|---|---|---|---|
| POST | `/api/verify` | ✓ firma + expiración | ✓ revocation local | Verificar contra claves locales + comprobar la lista de revocation de este servidor |
| POST | `/api/verify-external` | ✓ firma + expiración | — | Obtener JWKS entre orígenes y verificar según la especificación §12 |
| POST | `/api/verify-chain` | ✓ firma + expiración | ✓ recorrido completo de revocation del[] | Verificar + obtener la lista de revocation del issuer de cada entrada del[] |
| POST | `/api/decode` | — | — | Decodificar el payload — sin verificación de firma |

**La distinción entre estos endpoints es importante.** `/api/verify-external` ejecuta el algoritmo de verificación de la especificación §12: firma, expiración, integridad estructural del `del[]` (garantizada por la firma externa). Esto es lo que implementa un verifier conforme. `/api/verify-chain` agrega comprobación de estado en la capa de aplicación — obtiene la lista de revocation del issuer de cada entrada de `del[]` y confirma que ninguna ha sido revocada. Un token puede pasar la verificación del protocolo y fallar la verificación de cadena si la autorización de un delegante fue revocada desde que se emitió el token. Consulta `demo-del-verify.js` para una demostración paso a paso de esta distinción.

### Gestión de tokens y claves

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/token` | Crear un token firmado |
| GET | `/api/info` | Origen del servidor, kid, tipo de clave |
| GET | `/api/keys` | Configuración completa de claves incluyendo clave privada — solo para desarrollo, nunca exponer |
| POST | `/api/keys/generate` | Regenerar claves |
| POST | `/api/keys/import` | Restaurar una configuración de claves anterior |

## Argumentos

### `http.js`

```
--port=8888          Puerto en el que escuchar (predeterminado: 8888)
--hwt-keys=filename  Ruta del archivo de claves para persistencia entre reinicios
```

Sin `--hwt-keys`, las claves se generan en memoria y se pierden al reiniciar. Por defecto se generan claves Ed25519.

## Relacionado

- [Especificación del Protocolo HWT](../hwt-protocol/)
- [Biblioteca de referencia hwtr-js](../hwtr-js/)

## Licencia

Apache License 2.0 — ver [LICENSE](./LICENSE).


