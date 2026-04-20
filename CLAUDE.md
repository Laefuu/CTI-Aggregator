# CLAUDE.md — CTI Aggregator

Instructions pour l'assistant IDE sur ce projet.
Ce fichier est la source de vérité pour toutes les décisions d'architecture et de style.
**Lire en entier avant toute modification de code.**

---

## Contexte projet

Plateforme CTI (Cyber Threat Intelligence) on-premise qui :
1. Collecte des sources hétérogènes (RSS, PDF, MISP, TAXII, APIs)
2. Normalise les données en objets STIX 2.1 via un LLM local (Ollama)
3. Déduplique et corrèle les objets entre sources
4. Expose les données aux analystes CTI et SOC via un dashboard et une API

**Contrainte absolue** : le LLM tourne localement. Aucune donnée ne quitte le serveur vers un LLM cloud. Aucune dépendance à un service externe sauf pour la collecte de données.

Documents de référence (dans `docs/`) :
- `docs/CDC_v0.2.md` — Cahier des charges
- `docs/DAT_v0.2.md` — Document d'Architecture Technique
- `docs/PLAN_v1.0.md` — Plan d'implémentation

---

## Stack technique

| Domaine | Choix |
|---|---|
| Langage | Python 3.12, typage strict (`mypy --strict`) |
| Dépendances | uv (`uv add`, `uv run`) — jamais `pip install` directement |
| LLM runtime | Ollama sur `127.0.0.1:11434` |
| LLM modèle | `llama3.3:70b-instruct-q4_K_M` (fallback : `mistral:7b-instruct-q4_K_M`) |
| Embeddings | `BAAI/bge-m3` via sentence-transformers |
| File de messages | Redis 7 Streams |
| Base de données | PostgreSQL 16 + pgvector 0.7 |
| ORM | SQLAlchemy 2.x async + asyncpg |
| Migrations | Alembic |
| API | FastAPI (async) |
| Frontend | React 18 + Vite + TailwindCSS |
| Tests | pytest + pytest-asyncio |
| Linting | ruff + mypy |
| Conteneurs | Docker + Docker Compose v2 |

---

## Structure du monorepo

```
cti-aggregator/
├── modules/
│   ├── collector/       # Collecte sources externes
│   ├── preprocessor/    # Extraction texte, chunking
│   ├── llm_normalizer/  # Normalisation LLM → STIX 2.1
│   ├── validator/       # Validation schéma + scoring confiance
│   ├── deduplicator/    # Déduplication exacte + sémantique
│   ├── store/           # Persistance PostgreSQL
│   ├── enricher/        # Enrichissement VirusTotal / Shodan
│   └── api/             # FastAPI REST + alerting
├── frontend/            # React 18 + Vite
├── shared/
│   ├── models/          # Modèles Pydantic partagés (STIX, messages)
│   ├── queue/           # Abstractions Redis Streams
│   ├── metrics.py       # record_metric() partagé
│   └── config/          # Chargement .env
├── infra/
│   ├── docker-compose.yml
│   ├── postgres/        # init.sql, migrations Alembic
│   ├── redis/           # redis.conf
│   ├── nginx/           # cti.conf, certs/
│   └── ollama/          # benchmark.md
├── tests/
│   ├── unit/
│   ├── integration/
│   └── golden_dataset/  # 50 articles annotés pour évaluation LLM
├── docs/
├── Makefile
└── pyproject.toml
```

---

## Règles d'architecture — à ne jamais enfreindre

### Isolation des modules
- Un module **n'importe jamais** depuis un autre module. Les imports croisés sont interdits.
- Les modèles partagés viennent exclusivement de `shared/models/`.
- Les modules communiquent **uniquement** via Redis Streams — jamais d'appel direct.

### Streams Redis et ownership
Chaque stream a un producteur unique et un consommateur unique :

| Stream | Producteur | Consommateur |
|---|---|---|
| `cti:raw` | collector | preprocessor |
| `cti:chunks` | preprocessor | llm_normalizer |
| `cti:stix_raw` | llm_normalizer | validator |
| `cti:stix_valid` | validator | deduplicator |
| `cti:stix_rejected` | validator | — (log uniquement) |
| `cti:stix_final` | deduplicator | store |
| `cti:enrichment` | store | enricher |
| `cti:alerts` | store | api (alerting) |

Ne jamais écrire dans un stream depuis un module qui n'en est pas le producteur désigné.

### LLM — isolation réseau
- Ollama écoute sur `127.0.0.1:11434` uniquement.
- Le module `llm_normalizer` accède à Ollama via `http://127.0.0.1:11434`.
- Aucun autre module ne doit appeler Ollama.
- `llm_normalizer` n'a **aucun accès réseau externe** — vérifier dans le docker-compose que `network_mode: host` est utilisé uniquement pour accéder au loopback, pas pour sortir vers Internet.

### Secrets
- Jamais de secret en dur dans le code.
- Jamais de secret dans les logs (structlog filtre les champs `secret=True`).
- Tous les secrets passent par les variables d'environnement définies dans `.env`.

---

## Conventions Python

### Style général
```python
# ✅ Correct
async def fetch_iocs(
    session: AsyncSession,
    stix_type: str,
    min_confidence: int = 0,
) -> list[StixObject]:
    ...

# ❌ Interdit — pas de type hints = erreur mypy
def fetch_iocs(session, stix_type, min_confidence=0):
    ...
```

- Typage strict partout, y compris les retours `None` : `-> None`
- Pas de `# type: ignore` sans commentaire explicatif sur la même ligne
- Imports absolus uniquement (pas de `from ..models import ...`)
- Une classe par fichier pour les classes importantes, fonctions utilitaires regroupées

### Async
- Tout ce qui touche à I/O (DB, Redis, HTTP) est `async def`
- Utiliser `asyncio.gather()` pour les opérations parallèles indépendantes
- Ne jamais appeler `asyncio.run()` à l'intérieur d'une coroutine existante

### Logging
Utiliser **structlog** partout, jamais `print()` ni `logging` standard :

```python
import structlog
log = structlog.get_logger()

# ✅ Correct — champs nommés, pas de f-string
log.info("chunk_processed",
    source_id=str(chunk.source_id),
    chunk_index=chunk.chunk_index,
    objects_produced=len(objects),
    llm_duration_ms=duration,
)

# ❌ Interdit
print(f"Chunk processed: {chunk.source_id}")
log.info(f"Chunk processed: {chunk.source_id}")
```

### Métriques
Après chaque opération significative, enregistrer une métrique :

```python
from shared.metrics import record_metric

await record_metric("llm.objects_produced", len(objects), stix_type="indicator")
await record_metric("validator.rejected", 1, reason="invalid_ipv4")
```

Le paramètre `module` est inféré depuis la variable d'environnement `MODULE_NAME`.

### Modèles Pydantic
- Tous les modèles sont dans `shared/models/`
- Utiliser `model_config = ConfigDict(frozen=True)` pour les messages inter-modules (immutables)
- Les validators Pydantic utilisent `@field_validator` (Pydantic v2), jamais `@validator`

### Gestion des erreurs
```python
# ✅ Exceptions spécifiques, pas Exception générique
class CollectorError(Exception): ...
class LLMParseError(Exception): ...

# ✅ Toujours logger avant de re-lever ou d'absorber
except CollectorError as e:
    log.error("collect_failed", source_id=str(source.id), error=str(e))
    raise

# ❌ Absorber silencieusement
except Exception:
    pass
```

---

## Schéma de données — points clés

### Tables principales
- `stix_objects` — objets STIX 2.1 en JSONB, avec `confidence` (0–100), `tlp_level`, `is_merged`
- `object_sources` — provenance de chaque objet (N sources pour 1 objet après merge)
- `stix_embeddings` — vecteurs BGE-M3 (1024 dims) pour déduplication sémantique
- `sources` — sources configurées avec `category` (`trusted`/`known`/`unknown`)
- `perimeters` — périmètres de surveillance avec `ioc_values TEXT[]`
- `alerts` — alertes avec statut (`new`/`acked`/`false_positive`)
- `pipeline_metrics` — métriques pipeline (remplace Prometheus)

### Score de confiance — 4 dimensions (total 100 pts)
1. **Fiabilité source** (35 pts) : `trusted`=35, `known`=18, `unknown`=0
2. **Fraîcheur** (25 pts) : <24h=25, <7j=17, <30j=8, ≥30j=0
3. **Corroboration** (20 pts) : ≥3 sources=20, 2 sources=10, 1 source=0
4. **Qualité LLM** (20 pts) : 0 hallucinations=20, 1=15, 2=10, ≥3=0 ; cohérence type/contenu (threat-actor sans nom ou indicator sans pattern → 0)

Le détail du score est exposé dans `stix_data.x_cti_confidence_detail` (JSON avec les 4 composantes).
Le score est **recalculé à chaque merge** — une source supplémentaire augmente la corroboration.

### Types STIX produits par le LLM
`indicator`, `threat-actor`, `attack-pattern`, `relationship`, `report`

### Champs d'extension obligatoires sur chaque objet STIX produit
- `x_cti_source_url` — URL de la source (propagée par le LLM depuis le prompt)
- `x_cti_published_at` — date de publication (idem)

Ces champs sont validés par le Validator : écart avec les métadonnées du message Redis = alerte hallucination.

---

## LLM Normalizer — règles de prompt

### Paramètres d'inférence fixes
```python
{
    "temperature": 0.0,   # Déterminisme absolu — ne jamais changer
    "top_p": 1.0,
    "num_ctx": 8192,
    "format": "json",     # Mode JSON natif Ollama
}
```

### Logique de retry
- Maximum **2 retries** sur JSON invalide
- Le retry inclut le message d'erreur JSON dans le prompt de reprise
- Après 2 échecs : retourner `[]`, logger `llm.failure`, **ne pas bloquer le pipeline**

### Ce que le LLM ne doit jamais faire
- Inventer des IoCs non présents dans le texte
- Retourner du texte avant ou après le JSON
- Utiliser des balises Markdown (```json```)

Si le LLM produit systématiquement l'un de ces comportements sur un type de source particulier : ouvrir une issue et documenter dans `infra/ollama/benchmark.md`, ne pas contourner silencieusement.

---

## Déduplication — règles

### Niveau 1 — Exact match (Redis)
Clé de déduplication :
```python
SHA256(normalize(type + ":" + value))
# normalize = lowercase + strip
```
TTL des clés Redis : 60 jours (aligné sur la politique de rétention).

### Niveau 2 — Sémantique (pgvector)
- Uniquement sur `threat-actor` et `attack-pattern`
- Modèle : BGE-M3, seuil cosine : 0.92 (ajustable dans `.env`)
- Pas de merge automatique sans vérification : en cas de doute, préférer l'insertion

### Merge — principe immuable
Un merge **ne supprime jamais** l'objet original.
Il marque le doublon `is_merged=true` + `merged_into=<stix_id_cible>` et ajoute la source à l'objet canonique.

---

## Tests — conventions

### Structure
```
tests/
├── unit/           # Fonctions pures, règles métier — rapides, pas de DB ni Redis
├── integration/    # Pipeline complet avec DB et Redis de test
└── golden_dataset/ # Évaluation qualité LLM — slow tests
```

### Nommage
```python
# unit/test_validator_ioc_rules.py
def test_ipv4_private_range_rejected():
def test_ipv4_valid_public_accepted():
def test_domain_too_short_rejected():

# integration/test_pipeline_rss.py
async def test_rss_source_produces_stix_objects():
async def test_duplicate_fetch_skipped():
```

### Marqueurs pytest
```python
@pytest.mark.unit         # Rapide, no I/O
@pytest.mark.integration  # Nécessite DB + Redis
@pytest.mark.slow         # Golden dataset, >10s
```

Lancer uniquement les tests rapides en développement :
```bash
uv run pytest -m "unit" -v
```

### Fixtures
- La fixture `db_session` crée un schema de test et le rollback après chaque test
- La fixture `redis_client` utilise une DB Redis numérotée dédiée aux tests (db=1)
- Ne jamais utiliser la DB de production dans les tests

---

## Commandes utiles

```bash
# Développement
make up              # Démarrer tous les services
make down            # Arrêter
make logs            # Logs en temps réel
make migrate         # Appliquer les migrations Alembic

# LLM
make pull-model      # Télécharger llama3.3:70b-instruct-q4_K_M

# Tests
make test            # Tests unit + integration
make test-llm        # Golden dataset (lent)
uv run pytest -m unit -v --tb=short   # Tests rapides uniquement

# Qualité
make lint            # ruff + mypy
make audit           # pip-audit + safety

# Debug
make run-source SOURCE_ID=<uuid>   # Forcer une collecte manuelle
docker compose logs llm-normalizer -f --tail=50
```

---

## Environnement — variables requises

Voir `.env.example` pour la liste complète. Variables critiques à connaître :

| Variable | Usage |
|---|---|
| `LLM_MODEL` | Modèle Ollama principal |
| `LLM_FALLBACK_MODEL` | Modèle si le principal est indisponible |
| `DEDUP_SEMANTIC_THRESHOLD` | Seuil cosine déduplication (défaut: 0.92) |
| `TRUSTED_SOURCE_CATEGORIES` | Catégories de sources considérées `trusted` (JSON array) |
| `MODULE_NAME` | Nom du module courant (injecté par docker-compose, utilisé par `record_metric`) |

---

## Ce qu'il ne faut pas modifier sans discussion

Ces éléments ont des impacts en cascade et ne doivent pas être modifiés sans avoir relu le DAT et ouvert une discussion :

- Le schéma des messages Redis Streams (rupture de compatibilité entre modules)
- Le schéma DDL PostgreSQL (nécessite une migration Alembic)
- Le prompt système du LLM Normalizer (invalide le golden dataset)
- La formule de calcul du `confidence_score` (change tous les scores en base)
- Le modèle d'embedding BGE-M3 (invalide tous les vecteurs en base — nécessite un re-embedding complet)
- Le seuil de déduplication sémantique (impact sur tous les futurs merges)

---

## Checklist avant un PR

- [ ] `make lint` passe sans erreur (ruff + mypy --strict)
- [ ] `make test` passe sans régression
- [ ] Nouvelles fonctions/classes ont des type hints complets
- [ ] Pas de `print()` dans le code de production
- [ ] Pas de secret introduit dans le code
- [ ] Si modification du schéma DB : migration Alembic créée
- [ ] Si modification du prompt LLM : re-run `make test-llm` et résultats documentés
- [ ] Si nouveau connecteur : `BaseConnector` implémenté, ajouté au `CONNECTOR_REGISTRY`