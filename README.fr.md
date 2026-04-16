# hwt-demo

Serveur de développement et démos de scénarios pour le [protocole HWT (Hash Web Token)](../hwt-protocol/).

[documentation officielle](https://www.jimmont.com/hwt/hwt-demo) [issues](https://github.com/hwt-protocol/hwt-demo/issues)

HWT est un protocole de token d'autorisation sans état et inter-domaines. Tout domaine est un émetteur (issuer) valide. Les tokens sont vérifiables par quiconque peut atteindre les clés publiques de l'émetteur — aucun fournisseur central, aucune pré-configuration entre les parties.

## Démos

> Ces démos facilitent l'utilisation — elles ne constituent pas des références exhaustives ni une doctrine. Elles superposent des hypothèses applicatives sur le protocole (révocation (revocation), APIs de délégation, conventions serveur) qui sont utiles mais ne font pas partie de la spécification HWT. Pour ce que le protocole garantit effectivement, voir [SPEC.md](../hwt-protocol/SPEC.md). Pour le vocabulaire partagé, voir [CONVENTIONS.md](../hwt-protocol/CONVENTIONS.md).

### Démos de scénarios

- [demo-agent-chain.js](demo-agent-chain.js)            Chaîne de délégation d'agents IA
- [demo-del-verify.js](demo-del-verify.js)             Vérification de chaîne del[] et détection de lien révoqué
- [demo-multiparty.js](demo-multiparty.js)             Autorisation conjointe multi-parties
- [demo-federation.js](demo-federation.js)             Fédération inter-domaines spontanée
- [demo-mesh.js](demo-mesh.js)                   Chaîne de délégation de maillage de services
- [demo-partner-api.js](demo-partner-api.js)            Accès API partenaire et liaison d'audience
- [demo-edge.js](demo-edge.js)                   Vérification sans état en périphérie
- [demo-revocation-strategies.js](demo-revocation-strategies.js)  Tokens de courte durée vs révocation explicite — guide stratégique

### Bases de déploiement

Points de départ pour de vrais déploiements. Adapter à votre infrastructure. Ces scripts n'utilisent pas `demo_hosts.js` et n'appellent pas `ensureServers()` — ils sont autonomes.

- [demo-hono-deno.js](demo-hono-deno.js)        Deno + Hono — clés asymétriques (Ed25519 / ECDSA)
- [demo-hono-cloudflare.js](demo-hono-cloudflare.js)  Cloudflare Workers + Hono — clés asymétriques
- [demo-hmac-deno.js](demo-hmac-deno.js)        Deno — HMAC, mono-partie, sans infrastructure
- [demo-hmac-cloudflare.js](demo-hmac-cloudflare.js)  Cloudflare Workers — HMAC, secret partagé

HMAC est destiné aux déploiements mono-partie (spec §2). Utiliser les bases asymétriques pour tout ce qui nécessite une vérification inter-origines ou des chaînes de délégation (delegation chain).

## Prérequis

[Deno](https://deno.com/) — aucune autre dépendance.

## Démarrage rapide — démo inter-origines à deux instances

```sh
# Terminal A — serveur d'authentification
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8888 --hwt-keys=.hwt-keys-hosta.json

# Terminal B — deuxième service
deno run --allow-read=./ --allow-write=./ --allow-net=localhost ./http.js --port=8889 --hwt-keys=.hwt-keys-hostb.json
```

Ouvrir [http://localhost:8888](http://localhost:8888) et [http://localhost:8889](http://localhost:8889).

**À faire :** Créer un token sur A → le coller dans « Vérifier l'externe » sur B. B récupère le JWKS de A à l'exécution et vérifie la signature sans configuration préalable.

`--hwt-keys` sauvegarde la paire de clés dans un fichier pour que les tokens survivent aux redémarrages du serveur. L'omettre pour des clés en mémoire uniquement.

## Scripts de démo

Chaque script exécute un scénario complet contre des instances de serveur actives. `demo_hosts.js` les démarre automatiquement s'ils ne sont pas déjà en cours d'exécution (ports 8888, 8889, 8880) :

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

Ou démarrer les serveurs manuellement dans des terminaux séparés (voir le démarrage rapide ci-dessus), puis exécuter tout script de démo.

---

### [`demo-agent-chain.js`](demo-agent-chain.js) — Chaîne de délégation d'agents IA

Un utilisateur s'authentifie auprès d'un serveur d'authentification et délègue l'autorité à un agent IA sur un service distinct. Cet agent délègue à un sous-agent sur un troisième service. Le token final porte la chaîne de provenance cryptographique complète (`del[]`), couverte par la signature du token externe — infalsifiable sans coordinateur central. Chaque lien est vérifiable indépendamment contre les clés publiées de l'émetteur respectif.

Parcourt : création du token racine → délégation inter-serveurs (agent-1 sur hostB) → délégation au deuxième saut (agent-2 sur hostA) → vérification inter-origines du token final → révocation du token racine montrant l'invalidation de la chaîne en couche applicative.

---

### [`demo-del-verify.js`](demo-del-verify.js) — Vérification de chaîne del[]

Démontre la distinction entre la vérification protocolaire et la vérification de révocation en couche applicative — deux résultats distincts que la spec §12 sépare explicitement.

Après avoir construit une chaîne à deux sauts (`user:alice → svc:agent-1 → svc:agent-2`), le script révoque le token racine d'alice et montre le moment critique : la vérification protocolaire (`/api/verify-external`) réussit toujours — la signature externe est valide, ce qui est correct. La vérification de chaîne en couche applicative (`/api/verify-chain`) échoue — la liste de révocation de l'émetteur d'alice contient le `tid` révoqué. Le token externe n'a pas été re-signé ; sa signature reste valide. Seule la vérification d'état en couche applicative détecte l'invalidation.

La vérification de révocation est une fonctionnalité de bibliothèque construite au-dessus de HWT. La spec §13 place explicitement la révocation hors du périmètre protocolaire. Le protocole définit la structure de chaîne et la garantie de signature — ce que vous en faites vous appartient.

---

### [`demo-multiparty.js`](demo-multiparty.js) — Autorisation conjointe multi-parties

Deux organisations indépendantes émettent chacune des tokens d'approbateur à leurs propres principals. Un service coordinateur vérifie les deux tokens inter-origines contre le JWKS de chaque émetteur — aucun fournisseur d'identité partagé, aucun accord préalable entre les organisations. Ce n'est que lorsque les deux sont vérifiés que le coordinateur émet un token d'autorisation conjointe utilisant un schéma authz privé (spec §4.2) intégrant les deux identités d'approbateur. Tout service en aval peut vérifier le token du coordinateur et inspecter l'enregistrement de quorum depuis le token seul, sans recontacter les émetteurs d'origine.

Démontre pourquoi `del[]` ne s'applique pas ici : c'est une chaîne de délégation linéaire sans forme multi-parent. Les identités des approbateurs sont des données applicatives dans `authz`, pas des enregistrements de délégation protocolaires. Montre également que la révocation du token racine d'une partie auprès de son émetteur ne se propage pas au dépôt de tokens du coordinateur — l'état de chaque token est géré auprès de son propre émetteur (spec §13).

---

### [`demo-federation.js`](demo-federation.js) — Fédération inter-domaines spontanée

Deux émetteurs HWT quelconques interopèrent dès lors que les deux publient des points de terminaison well-known conformes — aucun enregistrement, aucun secret partagé, aucun accord de fédération. Ce script vérifie les tokens dans les deux sens : token de hostA vérifié chez hostB, token de hostB vérifié chez hostA. Ni l'un ni l'autre n'est le fournisseur d'identité de l'autre ; le même algorithme spec §12 s'exécute identiquement dans les deux sens.

Démontre également la découverte de métadonnées d'origine (`/.well-known/hwt.json`, spec §7) : ce que contient le document, ce que signifie chaque champ, et ce que font les vérificateurs en son absence (appliquer les valeurs par défaut de champ documentées et continuer — spec §7).

---

### [`demo-mesh.js`](demo-mesh.js) — Chaîne de délégation de maillage de services

Authentification service-à-service à travers un maillage de trois services sans CA de maillage, sans mTLS et sans service mesh. Un token utilisateur du service d'authentification (hostA) transite par une passerelle (hostB) et un backend (hostC), chaque saut étant vérifié contre le JWKS du service précédent et re-délégué. Le token final porte des entrées `del[]` pour chaque intermédiaire — vérifiables indépendamment depuis le token seul.

`authz` est tracé explicitement à chaque saut : viewer → viewer → viewer. Le rôle ne change pas parce que la spec §8.1 est normative — l'authz d'un token dérivé doit être égal ou un sous-ensemble strict de l'authz du token sujet. La révocation à la racine effondre la chaîne en couche applicative.

---

### [`demo-partner-api.js`](demo-partner-api.js) — Accès API partenaire et liaison d'audience

Intégration API B2B sans credential partagé. Une organisation partenaire lit le `/.well-known/hwt.json` de l'API consommatrice pour découvrir ses exigences, puis émet un token avec `aud` lié à cette API spécifique et un `authz` tableau (spec §4.3) combinant un schéma RBAC avec le vocabulaire de juridiction de CONVENTIONS.md (`GDPR/2.0/DE`). L'API consommatrice vérifie inter-origines, puis applique la correspondance d'audience en couche applicative (spec §12 étape 9).

Le chemin de non-correspondance `aud` est démontré explicitement : un token cryptographiquement valide lié à un service différent est refusé en couche applicative après que la vérification de signature réussit. C'est la mitigation du confused deputy (spec §11.4).

Couvre également : `authz_evaluation: "all"` exigeant que les deux schémas satisfassent l'évaluation ; et l'avertissement de CONVENTIONS.md selon lequel porter une déclaration de juridiction n'est pas une conformité — c'est un vocabulaire structurel.

---

### [`demo-edge.js`](demo-edge.js) — Vérification sans état en périphérie

Le même token vérifié indépendamment sur deux nœuds (hostB, hostC) sans aucun aller-retour vers l'émetteur (hostA) après la récupération initiale du JWKS.

Couvre également : la re-récupération forcée en cas de `kid` introuvable et son exigence de limitation de débit (spec §6, §11.7) ; le compromis de sécurité entre émetteur pré-enregistré et émetteur inconnu (spec §11.1, §11.2, §A.7) et pourquoi la pré-registration est la posture de production recommandée.

---

### [`demo-revocation-strategies.js`](demo-revocation-strategies.js) — Guide de stratégie de révocation

La question pratique la plus courante pour les adoptants : quand raccourcir la durée de vie du token plutôt que de construire un système de révocation ? Trois stratégies démontrées avec des tokens actifs :

- **Tokens de courte durée** — un token de 5 secondes expire à l'écran. Zéro infrastructure. La fenêtre d'exposition est égale à la durée de vie du token. C'est le mécanisme principal (spec §1).
- **Révocation explicite** — un token d'une heure est rejeté en quelques secondes après émission. Invalidation immédiate. Coût infrastructure : point de terminaison de révocation sur le chemin critique de vérification.
- **Hybride** — un token de 15 minutes. Le cas normal utilise l'expiration naturelle. La révocation gère uniquement les cas limites. La valeur par défaut pratique pour la plupart des systèmes en production.

Inclut une matrice de décision indexée par contexte de déploiement (API financière, session utilisateur générale, service interne, délégation d'agent à longue durée) utilisant les plages de durée de vie de la spec §A.1, et quatre questions auxquelles un adoptant doit répondre avant de choisir une stratégie. Présente la révocation comme un complément à une durée de vie bien choisie, pas un substitut.

---

## Points de terminaison du serveur

`http.js` est un serveur de développement et de démonstration. Il n'est pas durci pour la production.

### Points de terminaison protocolaires (définis par la spec)

| Méthode | Chemin | Spec | Description |
|---|---|---|---|
| GET | `/.well-known/hwt-keys.json` | §6 | Clés publiques JWKS — requises pour la vérification inter-origines |
| GET | `/.well-known/hwt.json` | §7 | Métadonnées de l'émetteur — schémas authz, politique aud, profondeur de délégation, déclarations de points de terminaison |

### Points de terminaison d'extension de bibliothèque

Ces points de terminaison implémentent des comportements superposés au protocole. La révocation et la délégation sont des préoccupations applicatives — la spec §13 les place explicitement hors du périmètre protocolaire.

| Méthode | Chemin | Description |
|---|---|---|
| GET | `/.well-known/hwt-revoked.json` | Liste de révocation — déclarée dans `hwt.json` sous `endpoints.revocation` |
| POST | `/api/token/delegate` | Créer un token délégué — remplit `del[]` selon les règles de construction de chaîne de la spec §8.1 |
| POST | `/api/revoke` | Révoquer un token par `tid` ou chaîne de token |
| POST | `/api/revoke/clear` | Vider la liste de révocation — commodité de développement |

### Points de terminaison de vérification

| Méthode | Chemin | Protocole | Couche applicative | Description |
|---|---|---|---|---|
| POST | `/api/verify` | ✓ sig + expiry | ✓ révocation locale | Vérifier contre les clés locales + vérifier la liste de révocation de ce serveur |
| POST | `/api/verify-external` | ✓ sig + expiry | — | Récupération et vérification JWKS inter-origines selon la spec §12 |
| POST | `/api/verify-chain` | ✓ sig + expiry | ✓ parcours complet de révocation del[] | Vérifier + récupérer la liste de révocation de l'émetteur de chaque entrée del[] |
| POST | `/api/decode` | — | — | Décoder le payload — sans vérification de signature |

**La distinction entre ces points de terminaison est importante.** `/api/verify-external` exécute l'algorithme de vérification spec §12 : signature, expiration, intégrité structurelle de `del[]` (garantie par la signature externe). C'est ce qu'implémente un vérificateur conforme. `/api/verify-chain` ajoute en plus la vérification d'état en couche applicative — il récupère la liste de révocation de l'émetteur de chaque entrée `del[]` et confirme qu'aucune n'est révoquée. Un token peut réussir la vérification protocolaire et échouer la vérification de chaîne si l'autorisation d'un délégant a été révoquée depuis l'émission du token. Voir `demo-del-verify.js` pour une démonstration étape par étape de cette distinction.

### Gestion des tokens et des clés

| Méthode | Chemin | Description |
|---|---|---|
| POST | `/api/token` | Créer un token signé |
| GET | `/api/info` | Origine du serveur, kid, type de clé |
| GET | `/api/keys` | Configuration complète des clés incluant la clé privée — développement uniquement, ne jamais exposer |
| POST | `/api/keys/generate` | Régénérer les clés |
| POST | `/api/keys/import` | Restaurer une configuration de clés précédente |

## Arguments

### `http.js`

```
--port=8888          Port d'écoute (défaut : 8888)
--hwt-keys=filename  Chemin du fichier de clés pour la persistance entre les redémarrages
```

Sans `--hwt-keys`, les clés sont générées en mémoire et perdues au redémarrage. Les clés Ed25519 sont générées par défaut.

## Liens connexes

- [Spécification du protocole HWT](../hwt-protocol/)
- [Bibliothèque de référence hwtr-js](../hwtr-js/)

## Licence

Licence Apache 2.0 — voir [LICENSE](./LICENSE.md).
