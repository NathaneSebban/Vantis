# Vantis

Scanner de vulnérabilités modulaire à plugins, combinant :
- 🔍 **Reconnaissance** — énumération de sous-domaines (crt.sh), scan de ports courants, fingerprinting de technologies
- 🌐 **Tests web** — headers de sécurité, XSS réfléchi, injection SQL (détection non-destructive), fichiers/chemins sensibles exposés
- 🧩 **Templates CVE** — moteur façon Nuclei, détection basée sur des templates YAML

Conçu pour le **bug bounty** et les tests d'intrusion **autorisés**.

Vantis s'utilise de deux façons, au choix :
- **CLI** — un scanner en ligne de commande autonome (aucune dépendance web).
- **Stack web** — une **API REST** (FastAPI) et une **interface React** pour lancer des scans depuis le navigateur, suivre les résultats **en temps réel** (WebSocket) et parcourir l'historique.

<!-- SCREENSHOT -->
<!-- Remplacez cette ligne par une capture/GIF de l'interface, ex :
     ![Interface Vantis](docs/screenshot.png) -->

## ⚠️ Avertissement légal — à lire avant toute utilisation

**Ce projet ne doit être utilisé que sur des cibles pour lesquelles vous avez une autorisation explicite** :
un programme de bug bounty dont le scope couvre la cible, un contrat de pentest signé, ou un actif que vous possédez vous-même.

Scanner un système sans autorisation est **illégal dans la plupart des juridictions**, y compris pour de la reconnaissance passive agressive ou des tests non-destructifs. L'outil affiche un avertissement et demande une confirmation explicite avant chaque scan — ce n'est pas un détail cosmétique, c'est une garde-fou volontaire.

Cette garde-fou existe partout :
- **CLI** — prompt interactif d'autorisation (ou drapeau `--yes-i-am-authorized` que vous tapez vous-même).
- **API** — le champ `"authorized": true` est **obligatoire** dans `POST /api/scans` ; sinon la requête est refusée (400).
- **Interface web** — une case à cocher explicite « Je confirme être autorisé à tester cette cible », non contournable : le bouton *Lancer le scan* reste désactivé tant qu'elle n'est pas cochée.

L'auteur décline toute responsabilité en cas d'utilisation non autorisée de cet outil.

## Installation

### Option A — CLI seul (le plus léger)

Aucune dépendance web, juste Python ≥ 3.10 :

```bash
git clone https://github.com/<votre-user>/vantis.git
cd vantis
pip install -e .
```

Utilisation :

```bash
# Scan complet (recon + web + cve)
vantis --target https://exemple-autorise.com

# Uniquement web + cve, avec sortie HTML
vantis --target https://exemple-autorise.com --modules web,cve --output rapport.html

# Élargir le scope à des sous-domaines connus
vantis --target exemple.com --scope exemple.com,api.exemple.com,staging.exemple.com

# Mode verbeux + rapport JSON
vantis --target https://exemple-autorise.com -v --output rapport.json
```

À l'exécution, l'outil demande une confirmation explicite d'autorisation avant de lancer le moindre test actif.

### Option B — Stack web complète via Docker (le plus simple à démontrer)

Une seule commande construit et lance l'API et l'interface :

```bash
docker compose up --build
```

Puis ouvrez :
- **Interface web** : <http://localhost:8080>
- **API REST** : <http://localhost:8080/api>
- **Documentation interactive (Swagger)** : <http://localhost:8080/api/docs>

Le frontend (nginx) sert l'application et fait office de reverse-proxy vers l'API, y compris pour le WebSocket temps réel — le navigateur ne parle qu'à une seule origine, sans CORS à configurer. La base SQLite est persistée dans un volume Docker.

### Option C — Stack web en développement (hot-reload)

Pour développer, on lance les deux serveurs séparément :

```bash
# 1) API (terminal 1)
pip install -e ".[api,dev]"
alembic upgrade head
uvicorn api.main:app --reload            # http://localhost:8000  (docs: /docs)

# 2) Frontend (terminal 2)
cd web
npm install
npm run dev                              # http://localhost:5173
```

Le serveur de dev Vite proxifie `/api` (REST + WebSocket) vers `http://localhost:8000`.

## API REST — aperçu

| Méthode | Route | Rôle |
|--------|-------|------|
| `POST` | `/api/scans` | Lance un scan (`authorized: true` obligatoire) → `202` + `scan_id` |
| `GET` | `/api/scans` | Historique paginé |
| `GET` | `/api/scans/{id}` | Statut + progression (module en cours, findings) |
| `GET` | `/api/scans/{id}/findings` | Findings, filtrables `?severity=` et `?module=` |
| `GET` | `/api/scans/{id}/report?format=json\|html\|md` | Export du rapport |
| `DELETE` | `/api/scans/{id}` | Annule un scan en cours, ou supprime l'historique |
| `WS` | `/api/scans/{id}/live` | Flux temps réel des findings pendant le scan |

Le scan tourne en tâche de fond ; l'API répond immédiatement et l'avancement est poussé en direct via le WebSocket.

## Configuration (variables d'environnement)

L'API se configure entièrement par l'environnement (ou un fichier `.env` à la racine, gitignoré). Tout a des valeurs par défaut adaptées au développement local.

| Variable | Défaut | Rôle |
|----------|--------|------|
| `VANTIS_DATABASE_URL` | `sqlite:///./vantis.db` | Base de données. Pour MySQL/WAMP : `mysql+pymysql://root:@localhost:3306/vantis` (nécessite `pip install -e ".[api,mysql]"`) |
| `VANTIS_CORS_ORIGINS` | origines Vite | Origines autorisées (jamais `*`), séparées par des virgules |
| `VANTIS_SCAN_RATE_LIMIT` | `5/hour` | Limite de création de scans par IP |
| `VANTIS_API_KEY` | *(vide = désactivé)* | Si défini, **authentification obligatoire** : header `X-API-Key` (et `?key=` pour le WebSocket). Côté frontend, fournir la même valeur via `VITE_API_KEY`. **À définir avant toute exposition réseau.** |
| `VANTIS_BLOCK_PRIVATE_TARGETS` | `false` | Si `true`, refuse les cibles en IP privée/loopback/réservée (anti-SSRF basique). Désactivé par défaut car un pentest interne autorisé vise légitimement des hôtes internes. |

### Utiliser MySQL / MariaDB (ex. WAMP + phpMyAdmin)

```bash
# 1) Driver
pip install -e ".[api,mysql]"

# 2) Créer la base "vantis" (interclassement utf8mb4_unicode_ci) dans phpMyAdmin

# 3) Pointer l'API dessus (dans .env) puis migrer
#    VANTIS_DATABASE_URL=mysql+pymysql://root:@localhost:3306/vantis
alembic upgrade head
```

Le driver SQLite reste le défaut : aucune installation supplémentaire n'est requise pour démarrer.

## Architecture

```
vantis/
├── core/
│   ├── engine.py         # orchestrateur, découverte des modules, gate d'autorisation
│   ├── plugin_base.py    # contrat ScanModule que chaque module implémente
│   ├── target.py         # validation de cible et de scope
│   └── report.py         # modèle de Finding + export JSON/Markdown/HTML
├── modules/
│   ├── recon/            # subdomain_enum, port_scan, tech_detect
│   ├── web/               # headers_check, xss_check, sqli_check, exposed_paths
│   └── cve/               # template_engine.py (moteur) + runner.py (module)
└── utils/
    └── http_client.py     # client HTTP partagé, rate-limité, User-Agent identifiable

api/                        # API REST (FastAPI) — adapte le moteur pour le web
├── main.py                 # app FastAPI, CORS, rate-limiting, cycle de vie
├── routers/scans.py        # endpoints /api/scans + WebSocket
├── models.py / schemas.py  # ORM SQLAlchemy / schémas Pydantic
├── scan_runner.py          # exécution en tâche de fond (thread pool)
└── websocket_manager.py    # diffusion des events en temps réel

web/                        # Interface React (Vite + TypeScript + Tailwind)
├── src/pages/              # NewScan, ScanLive, ScanReport, ScanHistory
├── src/components/         # AuthorizationGate, FindingCard, SeverityChart…
└── src/hooks/              # useScans (react-query), useScanWebSocket
```

La bibliothèque `vantis/` reste la **source de vérité** : l'API et l'interface ne font que l'exposer. Le moteur n'a reçu qu'un hook d'observation optionnel (`progress_callback`), rétro-compatible avec le CLI.

## Tests

```bash
# Backend (moteur + API) — pytest
pip install -e ".[api,dev]"
pytest

# Frontend — Vitest + React Testing Library
cd web && npm test
```

Les tests API utilisent un moteur factice : **aucun trafic réseau n'est émis** pendant la suite de tests. Le test de `AuthorizationGate` vérifie explicitement que le bouton de lancement reste désactivé tant que la case d'autorisation n'est pas cochée.

## Écrire un nouveau module

Il suffit d'ajouter une classe dans `vantis/modules/<catégorie>/` qui hérite de `ScanModule` :

```python
from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

class MyModule(ScanModule):
    name = "my-module"
    category = "web"  # ou "recon" / "cve"

    def run(self) -> list[Finding]:
        # ... logique du module ...
        return [Finding(module=self.name, title="...", severity=Severity.LOW, target=str(self.ctx.target))]
```

Le moteur le découvre automatiquement au démarrage, aucune autre modification n'est nécessaire.

## Écrire un nouveau template CVE

Les templates sont des fichiers YAML dans `templates/cve/`. Ils décrivent une requête et un matcher — voir les exemples fournis. Par conception, un template ne peut effectuer qu'une requête de **détection** (statut, header, contenu de la réponse) ; il ne peut pas encoder d'exploitation multi-étapes.

## Roadmap

- [ ] Détection de subdomain takeover
- [ ] Support d'authentification (cookies/tokens) pour scanner des zones authentifiées
- [ ] Export SARIF pour intégration CI/CD
- [ ] Détection de secrets dans le JS exposé
- [ ] Rate-limiting adaptatif basé sur les réponses 429

## Licence

MIT — voir [LICENSE](LICENSE).

## Contribuer

Les PR sont bienvenues, notamment pour de nouveaux modules ou templates CVE. Merci de garder l'esprit du projet : détection non-destructive uniquement.
