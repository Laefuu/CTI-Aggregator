# CTI Aggregator

Plateforme de Cyber Threat Intelligence (CTI) **on-premise** qui collecte des sources hétérogènes, normalise les données en objets STIX 2.1 via un LLM local, déduplique et corrèle les indicateurs, et les expose aux analystes via un dashboard et une API REST.

**Contrainte absolue** : tout tourne localement. Aucune donnée ne quitte le serveur vers un LLM cloud.

---

## Table des matières

- [Architecture](#architecture)
- [Stack technique](#stack-technique)
- [Pipeline de données](#pipeline-de-données)
- [Prérequis](#prérequis)
- [Installation et lancement](#installation-et-lancement)
- [Accès et authentification](#accès-et-authentification)
- [Référence des commandes](#référence-des-commandes)
- [Configuration (.env)](#configuration-env)
- [Score de confiance](#score-de-confiance)
- [Développement frontend](#développement-frontend)

---

## Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │              Docker Compose Stack            │
                        │                                              │
  ┌──────────────┐      │  ┌──────────┐    ┌─────────────────────┐   │
  │   Analyste   │─────▶│  │  nginx   │───▶│   frontend (nginx)  │   │
  │  (navigateur)│      │  │  :80/443 │    │  React 18 + Vite    │   │
  └──────────────┘      │  └────┬─────┘    │  :5173              │   │
                        │       │           └─────────────────────┘   │
                        │       ▼                                      │
                        │  ┌──────────┐                               │
                        │  │   API    │  FastAPI + JWT                │
                        │  │  :8000   │                               │
                        │  └────┬─────┘                               │
                        │       │                                      │
                        │  ┌────▼────────────────────────────────┐   │
                        │  │         Redis 7 Streams              │   │
                        │  │  (bus de messages inter-modules)     │   │
                        │  └────┬───┬───┬───┬───┬───┬───┬───┬───┘   │
                        │       │   │   │   │   │   │   │   │        │
                        │  ┌────▼┐ ┌▼──┐ ┌─▼─┐ ┌▼─┐ ┌─▼─┐ ┌▼──┐   │
                        │  │col- │ │pre│ │llm│ │val│ │de-│ │sto│   │
                        │  │lect │ │pro│ │nor│ │ida│ │dup│ │ re│   │
                        │  └─────┘ └───┘ └─┬─┘ └───┘ └───┘ └─┬─┘   │
                        │                   │                   │      │
                        │  ┌────────────────▼─────────────────▼─┐   │
                        │  │           PostgreSQL 16              │   │
                        │  │   STIX objects · pgvector · metrics  │   │
                        │  └──────────────────────────────────────┘   │
                        │                                              │
                        │  ┌──────────┐   ┌──────────────────────┐   │
                        │  │ enricher │   │       Ollama          │   │
                        │  │ VT/Shodan│   │ llama3.3:70b (host)   │   │
                        │  └──────────┘   └──────────────────────┘   │
                        └─────────────────────────────────────────────┘
```

### Services

| Service | Port | Rôle |
|---|---|---|
| **frontend** | 5173 | Dashboard React — SPA servie via nginx, proxy vers l'API |
| **api** | 8000 | FastAPI REST — auth JWT, sources, objets STIX, alertes, métriques |
| **nginx** | 80 / 443 | Reverse proxy HTTP/HTTPS, gateway vers l'API |
| **collector** | — | Collecte planifiée des sources (RSS, PDF, MISP, TAXII, API) |
| **preprocessor** | — | Extraction de texte, OCR, découpage en chunks |
| **llm-normalizer** | — | Normalisation en STIX 2.1 via Ollama (réseau host) |
| **validator** | — | Validation schéma, règles IoC, calcul du score de confiance |
| **deduplicator** | — | Déduplication exacte (Redis) + sémantique (pgvector) |
| **store** | — | Persistance PostgreSQL, surveillance périmètre, alertes |
| **enricher** | — | Enrichissement VirusTotal / Shodan / NVD à la demande |
| **postgres** | 5432 | Base de données principale (pgvector 0.7) |
| **redis** | 6379 | Bus de messages (Streams) + cache déduplication |
| **ollama** | 127.0.0.1:11434 | Inférence LLM locale (réseau host pour accès GPU) |

---

## Stack technique

| Domaine | Choix |
|---|---|
| Langage | Python 3.12, typage strict (mypy --strict) |
| Dépendances Python | uv |
| LLM runtime | Ollama — `llama3.3:70b-instruct-q4_K_M` (fallback : `mistral:7b-instruct`) |
| Embeddings | `BAAI/bge-m3` via sentence-transformers (1024 dims) |
| File de messages | Redis 7 Streams (consumer groups, at-least-once delivery) |
| Base de données | PostgreSQL 16 + pgvector 0.7 |
| ORM | SQLAlchemy 2.x async + asyncpg |
| Migrations | Alembic |
| API | FastAPI async + Uvicorn |
| Frontend | React 18 + Vite 5 |
| Conteneurs | Docker + Docker Compose v2 |
| Logging | structlog (JSON structuré) |
| Tests | pytest + pytest-asyncio |
| Qualité | ruff + mypy --strict |

---

## Pipeline de données

Chaque module est un service Docker autonome qui consomme un stream Redis, traite, et publie dans le stream suivant.

```
Source externe
     │
     ▼
┌─────────────┐
│  collector  │  Scraping / RSS / PDF / TAXII / MISP
└──────┬──────┘  Déduplication URL (Redis, TTL 7 jours)
       │ cti:raw  {url, contenu base64, métadonnées source}
       ▼
┌─────────────┐
│ preprocessor│  Extraction texte (trafilatura, PyMuPDF)
└──────┬──────┘  OCR si activé · détection langue · chunking (3000 tokens)
       │ cti:chunks  {texte, chunk_index, langue, source_url, published_at}
       ▼
┌──────────────────┐
│  llm-normalizer  │  Prompt STIX 2.1 → Ollama (llama3.3:70b)
└────────┬─────────┘  temperature=0 · format JSON natif · 2 retries max
         │ cti:stix_raw  {objets STIX bruts, modèle, durée ms}
         ▼
┌───────────┐
│ validator │  Validation schéma STIX · règles IoC (ex: pas d'IP privées)
└─────┬─────┘  Calcul score de confiance (4 dimensions, 0–100)
      │ cti:stix_valid   → objets acceptés
      │ cti:stix_rejected → objets rejetés (log)
      ▼
┌──────────────┐
│ deduplicator │  Niveau 1 : SHA256(type+valeur) → clé Redis (TTL 60 j)
└──────┬───────┘  Niveau 2 : cosine similarity BGE-M3 (seuil 0.92)
       │                     uniquement pour threat-actor et attack-pattern
       │ cti:stix_final  {action: INSERT|MERGE, stix_id_cible}
       ▼
┌───────┐
│ store │  INSERT dans stix_objects · mise à jour object_sources
└───┬───┘  Surveillance périmètre → cti:alerts
    │      Requêtes enrichissement → cti:enrichment
    ▼
PostgreSQL (stix_objects, object_sources, stix_embeddings, alerts)

┌──────────┐
│ enricher │  Consomme cti:enrichment (déclenché par le bouton "Enrichir")
└──────────┘  CVE → NVD API · IP → VirusTotal + Shodan · domaine → VirusTotal
              Résultat stocké dans stix_data.x_cti_enrichment (JSONB)
```

### Schéma principal PostgreSQL

| Table | Description |
|---|---|
| `stix_objects` | Objets STIX 2.1 (JSONB), score confiance, TLP, statut merge |
| `object_sources` | Provenance N→1 : chaque source ayant signalé un objet |
| `stix_embeddings` | Vecteurs BGE-M3 (1024 dims) pour déduplication sémantique |
| `sources` | Sources configurées (URL, type, fréquence, catégorie) |
| `perimeters` | Périmètres de surveillance (liste d'IoCs, secteurs) |
| `alerts` | Correspondances périmètre (statut : new / acked / false_positive) |
| `pipeline_metrics` | Métriques pipeline (remplace Prometheus, purge à 60 jours) |
| `users` | Comptes administrateurs (bcrypt) |

---

## Prérequis

- **Docker Engine** ≥ 24 et **Docker Compose** v2
- **WSL 2** (Windows) ou Linux natif
- **Ollama** accessible sur `http://10.100.8.11:11434` (configurable dans `.env`)
- 4 Go RAM minimum pour le stack (hors LLM)

---

## Installation et lancement

### 1. Cloner le dépôt

```bash
git clone <repo-url>
cd CTI-Aggregator
```

### 2. Configurer l'environnement

```bash
cp .env.example .env
# Éditer .env : mots de passe, URL Ollama, clés API (VirusTotal, Shodan)
```

Variables critiques à renseigner :

```ini
POSTGRES_PASSWORD=<mot de passe fort>
REDIS_PASSWORD=<mot de passe fort>
JWT_SECRET=<64 octets aléatoires en base64>
OLLAMA_BASE_URL=http://<ip-ollama>:11434
OLLAMA_BEARER_TOKEN=<token si authentification>
VIRUSTOTAL_API_KEY=<clé VT>
SHODAN_API_KEY=<clé Shodan>
```

Générer un secret JWT :
```bash
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(64)).decode())"
```

### 3. Builder et démarrer

```bash
make build    # construit toutes les images Docker (~5 min au premier build)
make up       # démarre les 13 services en arrière-plan
```

### 4. Appliquer les migrations

```bash
make migrate
```

### 5. Créer le premier compte admin

```bash
make bootstrap-admin EMAIL=admin@org.internal PASSWORD=<mot-de-passe>
```

### 6. Télécharger le modèle LLM (si Ollama est local)

```bash
make pull-model            # llama3.3:70b-instruct-q4_K_M (~24 Go)
make pull-model-fallback   # mistral:7b-instruct-q4_K_M (~4 Go)
```

---

## Accès et authentification

| Interface | URL |
|---|---|
| **Dashboard** | http://localhost:5173 |
| **API REST** | http://localhost:8000 |
| **Swagger UI** | http://localhost:8000/docs |
| **Health check** | http://localhost/health |

Authentification via JWT Bearer token :

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@org.internal","password":"<mot-de-passe>"}' \
  | jq .access_token
```

---

## Référence des commandes

### Infrastructure

```bash
make up                     # Démarrer tous les services
make down                   # Arrêter tous les services
make down-volumes           # Arrêter + supprimer les volumes (DESTRUCTIF)
make build                  # Rebuilder toutes les images
make build-no-cache         # Rebuild sans cache
make restart                # Redémarrer tous les services
make ps                     # État des conteneurs
make logs                   # Logs en temps réel (tous les services)
make logs-collector         # Logs d'un service spécifique
make up-infra               # Démarrer uniquement postgres, redis, ollama, nginx
```

### Base de données

```bash
make migrate                # Appliquer les migrations en attente
make migrate-down           # Rollback de la dernière migration
make migrate-status         # Voir l'état actuel des migrations
make migrate-history        # Historique complet
make migrate-new MSG="..."  # Créer une nouvelle migration
make shell-db               # Ouvrir psql (utilisateur cti)
```

### Redis

```bash
make shell-redis            # Ouvrir redis-cli
make streams                # Longueur de tous les streams cti:*
```

### LLM et modèles

```bash
make pull-model             # Télécharger le modèle principal
make pull-model-fallback    # Télécharger le modèle de secours
make list-models            # Lister les modèles disponibles
make benchmark-llm          # Benchmark de latence LLM
```

### Sources et collecte

```bash
make run-source SOURCE_ID=<uuid>   # Forcer une collecte immédiate
```

### Tests

```bash
make test                   # Tests unit + integration (rapides)
make test-unit              # Tests unitaires uniquement (pas de I/O)
make test-integration       # Tests d'intégration (nécessite postgres + redis)
make test-llm               # Évaluation qualité LLM sur golden dataset (lent)
make test-cov               # Tests avec rapport de couverture
```

### Qualité du code

```bash
make lint                   # ruff check + mypy --strict
make fmt                    # Formatage automatique (ruff)
make fmt-check              # Vérifier le formatage sans modifier
make audit                  # Audit sécurité des dépendances (pip-audit + safety)
```

### Nettoyage

```bash
make clean                  # Supprimer les caches Python (__pycache__, .mypy_cache, …)
make clean-dist             # Supprimer les artefacts de build
```

---

## Configuration (.env)

Toutes les variables sont dans `.env` à la racine. Le fichier `.env.example` contient les valeurs par défaut.

| Variable | Description |
|---|---|
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL |
| `REDIS_PASSWORD` | Mot de passe Redis |
| `JWT_SECRET` | Clé de signature JWT (64 octets base64) |
| `JWT_EXPIRE_HOURS` | Durée de validité des tokens (défaut : 8h) |
| `OLLAMA_BASE_URL` | URL de l'instance Ollama |
| `OLLAMA_BEARER_TOKEN` | Token d'auth Ollama (si activé) |
| `LLM_PRIMARY_MODEL` | Modèle principal (`llama3.3:70b-instruct-q4_K_M`) |
| `LLM_FALLBACK_MODEL` | Modèle de secours (`mistral:7b-instruct`) |
| `LLM_NUM_CTX` | Fenêtre de contexte LLM (défaut : 8192) |
| `EMBEDDING_MODEL` | Modèle d'embedding (`BAAI/bge-m3`) |
| `DEDUP_SEMANTIC_THRESHOLD` | Seuil cosine déduplication sémantique (défaut : 0.92) |
| `CHUNK_MAX_TOKENS` | Taille max d'un chunk (défaut : 3000) |
| `FETCH_DEDUP_TTL_SECONDS` | TTL cache URL collecte (défaut : 604800 = 7 jours) |
| `TRUSTED_SOURCE_CATEGORIES` | Catégories de sources « trusted » |
| `RETENTION_DAYS` | Durée de rétention des données (défaut : 60 jours) |
| `SMTP_HOST` | Serveur SMTP pour les alertes |
| `ALERT_RECIPIENTS` | Destinataires des alertes email |
| `VIRUSTOTAL_API_KEY` | Clé API VirusTotal (enrichissement désactivé si absent) |
| `SHODAN_API_KEY` | Clé API Shodan (enrichissement désactivé si absent) |
| `MISP_BASE_URL` / `MISP_API_KEY` | Instance MISP (optionnel) |

---

## Score de confiance

Chaque objet STIX reçoit un score de 0 à 100 calculé selon 4 dimensions :

| Dimension | Max | Critères |
|---|---|---|
| **Fiabilité source** | 35 pts | `trusted`=35, `known`=18, `unknown`=0 |
| **Fraîcheur** | 25 pts | <24h=25, <7j=17, <30j=8, ≥30j=0 |
| **Corroboration** | 20 pts | ≥3 sources=20, 2 sources=10, 1 source=0 |
| **Qualité LLM** | 20 pts | 0 hallucinations=20, 1=15, 2=10, ≥3=0 |

Le score est recalculé à chaque merge. Le détail est exposé dans `stix_data.x_cti_confidence_detail`.

---

## Développement frontend

Pour le développement avec hot-reload (sans rebuilder l'image Docker) :

```bash
make frontend-dev
```

Vite démarre sur `:5173` avec proxy vers l'API Docker (`http://localhost:8000`). Requiert Node ≥ 18 installé localement.

Pour rebuilder uniquement l'image frontend après des changements :

```bash
make frontend-build
make up
```

---

## Structure du projet

```
CTI-Aggregator/
├── modules/
│   ├── collector/       # Collecte sources externes
│   ├── preprocessor/    # Extraction texte, chunking, OCR
│   ├── llm_normalizer/  # Normalisation LLM → STIX 2.1
│   ├── validator/       # Validation schéma + scoring confiance
│   ├── deduplicator/    # Déduplication exacte + sémantique
│   ├── store/           # Persistance PostgreSQL
│   ├── enricher/        # Enrichissement VirusTotal / Shodan / NVD
│   └── api/             # FastAPI REST + alerting
├── frontend/            # React 18 + Vite (Dockerfile multi-stage)
├── shared/
│   ├── models/          # Modèles Pydantic partagés (STIX, messages Redis)
│   ├── queue/           # Abstractions Redis Streams
│   ├── metrics.py       # record_metric() partagé
│   └── config/          # Chargement .env (pydantic-settings)
├── infra/
│   ├── docker-compose.yml
│   ├── postgres/        # init.sql
│   ├── redis/           # redis.conf
│   ├── nginx/           # cti.conf (reverse proxy)
│   └── ollama/          # benchmark.md
├── tests/
│   ├── unit/            # Tests rapides, pas de I/O
│   ├── integration/     # Nécessite postgres + redis
│   └── golden_dataset/  # Évaluation qualité LLM (50 articles annotés)
├── Makefile
├── pyproject.toml
└── .env                 # Non versionné — à créer depuis .env.example
```
