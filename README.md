# Secure Log Stream Engine
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Project Level](https://img.shields.io/badge/Level-ING3-orange.svg)]()
[![Code Style](https://img.shields.io/badge/code%20style-PEP8-green.svg)](https://peps.python.org/pep-0008/)

## Présentation

**Secure Log Stream Engine** est une application Python en ligne de commande
permettant de générer, ingérer, transformer et analyser des fichiers de logs
HTTP. Elle a été conçue dans le cadre du cursus ING3 avec un objectif central :
traiter de gros volumes de données en limitant l'empreinte mémoire.

Le pipeline lit les fichiers progressivement grâce aux générateurs Python,
parse et normalise les entrées, puis produit des statistiques et des rapports
de sécurité. Il permet notamment de :

- compter les logs par catégorie, niveau de sévérité et utilisateur ;
- suivre les adresses IP actives, les IP en erreur et les IP blacklistées ;
- détecter les échecs de connexion consécutifs correspondant à une attaque par
  force brute ;
- mesurer le temps d'exécution et, sur demande, la consommation mémoire ;
- appliquer des règles de sécurité extensibles et exporter un rapport d'audit.

## Membres

Projet réalisé par :

- **STEPKOWSKI Maxime**
- **CHAMPION Enrike**
- **MASSION Côme**

## Architecture et modules techniques

Le projet est organisé en modules indépendants reliés par un pipeline de
traitement :

### Ingestion et parsing

Le package `log_engine` lit les fichiers du dossier `logs/` sous forme de flux
et les convertit en enregistrements structurés. Les générateurs (`yield` et
`yield from`) évitent de charger tous les fichiers en mémoire. Le parsing peut
être exécuté par plusieurs processus grâce à `--workers` et `--batch-size`.

### Transformation et routage

Le package `log_transformation` filtre les entrées invalides, normalise les
valeurs et conserve des exemples du traitement. Le routage des différents
formats d'enregistrements s'appuie sur le pattern matching `match/case`.

### Agrégation et analyse IP

Le package `log_engine.aggregation` calcule les compteurs par catégorie,
niveau et utilisateur. Le package `log_processing` utilise des `set` et des
`frozenset` pour comparer les IP observées avec `data/blacklist.txt` et
produire un rapport complet.

### Détection de force brute

Le module `log_process.brute_force` recherche, pour chaque IP, au moins trois
échecs de connexion consécutifs (`401` ou `403`). Les alertes peuvent être
détectées pendant l'analyse principale ou via la CLI dédiée.

### Moteur de sécurité et audit

Le package `security` regroupe les règles de détection d'IP blacklistées,
d'erreurs HTTP répétées et de force brute. Les règles sont passées au moteur
comme des fonctions, ce qui facilite leur extension. Un rapport texte peut
également contenir un audit des noms et types de variables inspectées, sans
exporter leurs valeurs.

## Menu CLI

Le menu interactif se lance depuis la racine du projet :

```bash
python log_analysis.py
```

Il propose les actions suivantes :

1. **Générer des logs** : choisir le nombre de fichiers, le nombre de lignes,
   la cadence, la taille des lots et le dossier de sortie.
2. **Lancer l'application principale** : choisir le nombre de processus et
   activer ou non le suivi détaillé de la mémoire.
3. **Lire les rapports** : sélectionner un rapport texte disponible dans
   `reports/` et le consulter page par page.
0. **Quitter**.

Dans la vue des rapports, les flèches gauche et droite changent de page et
`q` revient au menu précédent.

## Structure du projet

```text
log-analysis/
├── data/
│   └── blacklist.txt              # IP blacklistées
├── log_engine/                    # ingestion, parsing, mémoire, agrégation
├── log_generator/                 # génération d'un ou plusieurs fichiers
├── log_process/                   # détection de force brute et CLI associée
├── log_processing/                # collecte et comparaison des adresses IP
├── log_transformation/            # filtrage, normalisation et suivi
├── security/                      # règles, moteur et rapports de sécurité
├── logs/                          # fichiers de logs générés
├── reports/                       # rapports produits à l'exécution
├── tests/                         # tests unitaires
├── log_analysis.py                # menu interactif
├── main.py                        # pipeline d'analyse principal
├── requirements.txt               # dépendances du projet
└── README.md
```

## Installation

Les commandes suivantes doivent être exécutées depuis la racine du projet.

### Linux et macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Windows PowerShell

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Python 3.10 ou une version ultérieure est recommandée. Le fichier
`requirements.txt` contient notamment `pytest` pour exécuter les tests.

## Utilisation en ligne de commande

Générer un fichier de 1 000 lignes :

```bash
python -m log_generator.generate_logs --lines 1000 --number 1
```

Générer plusieurs fichiers dans `logs/` :

```bash
python -m log_generator.generate_multiple_logs \
  --files 3 \
  --lines 1000 \
  --output-dir logs
```

Lancer l'analyse principale :

```bash
python main.py
python main.py --memory --workers 4 --batch-size 5000
```

Options utiles :

- `--memory` active le suivi de la mémoire ;
- `--workers N` définit le nombre de processus de parsing ;
- `--batch-size N` définit la taille des lots ;
- `--quiet` masque les messages de progression ;
- `--ip-report-output chemin` choisit le rapport IP ;
- `--brute-force-output chemin` choisit le rapport force brute ;
- `--security-report chemin` active l'export du rapport de sécurité.

Détecter séparément les attaques par force brute :

```bash
python -m log_process.brute_force_cli
python -m log_process.brute_force_cli --directory autre_dossier
python -m log_process.brute_force_cli --pattern "*.log" --output reports/mon_rapport.txt
```

## Vérification

Exécuter les tests unitaires :

```bash
python -m pytest
```

Vérifier la syntaxe de l'ensemble du projet :

```bash
python -m compileall -q .
```

Afficher l'aide des différentes commandes :

```bash
python main.py --help
python -m log_generator.generate_logs --help
python -m log_generator.generate_multiple_logs --help
python -m log_process.brute_force_cli --help
```
