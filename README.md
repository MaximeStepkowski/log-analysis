# Secure Log Stream Engine - Plateforme d'Analyse de Logs en Temps Réel

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Project Level](https://img.shields.io/badge/Level-ING3-orange.svg)]()
[![Code Style](https://img.shields.io/badge/code%20style-PEP8-green.svg)](https://peps.python.org/pep-0008/)

## 📝 Description du Projet

**Secure Log Stream Engine** est une plateforme en ligne de commande (CLI) conçue pour l'ingestion, la transformation, l'analyse et la sécurisation en temps réel de journaux de logs volumineux. 

Développé dans le cadre du cursus **ING3**, ce projet répond à une contrainte majeure d'ingénierie : **traiter plusieurs millions de lignes de données système/réseau avec une empreinte mémoire (RAM) minimale et constante**. L'architecture s'appuie sur la programmation fonctionnelle, les générateurs Python et un moteur de règles d'audit modulaire.

---

## 👥 Équipe de Développement

Projet réalisé en trinôme par :
* **STEPKOWSKI Maxime** 
* **CHAMPION Enrike**
* **MASSION Côme** 
---

## ⚙️ Architecture & Modules Techniques

Le projet est découpé en 4 modules principaux respectant les prérequis d'optimisation et d'isolation :

### 1. Ingestion de Données & Générateurs Mémoire (`Module 1`)
* **Flux continu sans surcharge RAM** : Utilisation de générateurs `yield` pour lire les logs ligne par ligne à la demande.
* **Agrégation de sources multiples** : Sous-générateurs exploitant `yield from` pour chaîner la lecture de plusieurs fichiers.
* **Parsing & Modélisation** : Structuration sous forme de dictionnaires avec typage fort (horodatage, niveau de sévérité `INFO`/`WARNING`/`ERROR`/`CRITICAL`, IP source, utilisateur, payload).
* **Immutabilité** : Métadonnées réseau fixes modélisées sous forme de Tuples `(IP, Port, Protocole)`.

### 2. Pipeline de Transformation & Programmation Fonctionnelle (`Module 2`)
* **Filtrage Intelligent** : Utilisation de `filter()` et d'expressions `lambda` pour écarter les requêtes invalides ou nettoyer les lignes vides/corrompues.
* **Normalisation** : Application de `map()` pour le nettoyage des chaînes, la conversion de casse et le reformatage via f-strings.
* **Structural Pattern Matching** : Routage dynamique des entrées via `match-case` (gestion des chaînes brutes, dictionnaires et tuples de connexion).

### 3. Agrégation & Détection d'Attaques (`Module 3`)
* **Opérations sur Ensembles** : Utilisation de `set` et de `frozenset` immuables pour identifier les IP uniques en erreur et exécuter des opérations d'ensembles (`|`, `&`, `-`, `^`) avec des listes d'IP blacklistées.
* **Accumulation Dynamique** : Dénombrement par catégorie via `collections.defaultdict` afin d'éviter les `KeyError`.
* **Détection Brute-Force** : Algorithme de détection d'échecs de connexion consécutifs combinant des boucles `while`/`for` enrichies de la clause `else`.

### 4. Moteur de Règles & Introspection Dynamique (`Module 4`)
* **Flexible Rule Engine** : Moteur de sécurité configurable basé sur la fonction maître `apply_security_rules(*args, **kwargs)` traitant les fonctions comme des objets de première classe.
* **Audit Système & Introspection** : Export d'un rapport sur les variables de portée actuellement chargées en mémoire à l'aide des fonctions `globals()` et `locals()`.

---

## 📂 Structure du Projet

