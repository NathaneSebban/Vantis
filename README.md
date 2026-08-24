# Vantis

Scanner de vulnérabilités modulaire à plugins, combinant :
- 🔍 **Reconnaissance** — énumération de sous-domaines (crt.sh), scan de ports courants, fingerprinting de technologies
- 🌐 **Tests web** — headers de sécurité, XSS réfléchi, injection SQL (détection non-destructive), fichiers/chemins sensibles exposés
- 🧩 **Templates CVE** — moteur façon Nuclei, détection basée sur des templates YAML

Conçu pour le **bug bounty** et les tests d'intrusion **autorisés**.

## ⚠️ Avertissement légal — à lire avant toute utilisation

**Ce projet ne doit être utilisé que sur des cibles pour lesquelles vous avez une autorisation explicite** :
un programme de bug bounty dont le scope couvre la cible, un contrat de pentest signé, ou un actif que vous possédez vous-même.

Scanner un système sans autorisation est **illégal dans la plupart des juridictions**, y compris pour de la reconnaissance passive agressive ou des tests non-destructifs. L'outil affiche un avertissement et demande une confirmation explicite avant chaque scan — ce n'est pas un détail cosmétique, c'est une garde-fou volontaire.

L'auteur décline toute responsabilité en cas d'utilisation non autorisée de cet outil.

## Installation

```bash
git clone https://github.com/<votre-user>/vantis.git
cd vantis
pip install -e .
```

## Utilisation

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
```

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
