from typing import Any, Iterable, Iterator


# ============================================================
# CONSTANTES ET CRITERES DE FILTRAGE
# ============================================================

VALID_LEVELS = {"INFO", "WARNING", "ERROR", "CRITICAL"}

VALID_PROTOCOLS = {"TCP", "UDP"}

# ============================================================
# 2. FILTRAGE DES ENTREES VIDES
# ============================================================

def delete_empty_entries(logs: Iterable[Any]) -> Iterator[Any]:
    """
    Supprime les entrées vides ou None.
    Utilisation de filter(None, ...).
    """

    return filter(None, logs)


# ============================================================
# 3. VERIFICATION DE LA STRUCTURE DES LOGS
# ============================================================

def valid_log(log: Any) -> bool:
    """
    Vérifie que le log possède une structure exploitable.
    """

    if not isinstance(log, dict):
        return False

    # Vérification des champs principaux
    if not isinstance(log.get("timestamp"), str):
        return False

    if not log["timestamp"].strip():
        return False

    if log.get("level") not in VALID_LEVELS:
        return False

    if not isinstance(log.get("user"), str):
        return False

    if not isinstance(log.get("payload"), (dict, str)):
        return False

    # Vérification des métadonnées de connexion
    connection = log.get("connection")

    if not isinstance(connection, tuple) or len(connection) != 3:
        return False

    ip, port, protocol = connection

    if not isinstance(ip, str) or not ip.strip():
        return False

    if not isinstance(port, int) or isinstance(port, bool):
        return False

    if not 1 <= port <= 65535:
        return False

    if protocol not in VALID_PROTOCOLS:
        return False

    return True

# ============================================================
# 4. FILTRAGE INTELLIGENT DES NIVEAUX DE GRAVITE
# ============================================================

def filtering_by_level(
    logs: Iterable[dict],
    levels: set[str] | None = None
) -> Iterator[dict]:
    """
    Conserve uniquement les logs correspondant
    aux niveaux de gravité demandés.
    """

    if levels is None:
        levels = VALID_LEVELS

    return filter(
        lambda log: log["level"] in levels,
        logs
    )


# ============================================================
# 5. EXCLUSION DES ADRESSES IP
# ============================================================

def filtering_by_ip(
    logs: Iterable[dict],
    ip_blacklist: set[str] | None = None
) -> Iterator[dict]:
    """
    Exclut les connexions provenant des IP blacklistées.
    """

    if ip_blacklist is None:
        ip_blacklist = set()

    return filter(
        lambda log: log["connection"][0] not in ip_blacklist,
        logs
    )


# ============================================================
# 6. FILTRAGE PAR UTILISATEUR
# ============================================================

def filtering_by_user(
    logs: Iterable[dict],
    excluded_users: set[str] | None = None
) -> Iterator[dict]:
    """
    Exclut les logs provenant de certains utilisateurs.
    """

    if excluded_users is None:
        excluded_users = set()

    return filter(
        lambda log: log["user"] not in excluded_users,
        logs
    )


# ============================================================
# 7. FILTRAGE PAR PROTOCOLE
# ============================================================

def filtering_by_protocol(
    logs: Iterable[dict],
    protocols: set[str] | None = None
) -> Iterator[dict]:
    """
    Conserve uniquement les protocoles sélectionnés.
    """

    if protocols is None:
        protocols = VALID_PROTOCOLS

    return filter(
        lambda log: log["connection"][2] in protocols,
        logs
    )


# ============================================================
# 8. FILTRAGE PAR MOT-CLE
# ============================================================

def filtering_by_keyword(
    logs: Iterable[dict],
    keyword: str | None = None
) -> Iterator[dict]:
    """
    Recherche un mot-clé dans le message du payload.
    """

    if not keyword:
        return iter(logs)

    keyword = keyword.lower()

    def contient_mot_cle(log: dict) -> bool:

        payload = log["payload"]

        if isinstance(payload, dict):
            message = payload.get("message", "")
        else:
            message = payload

        return keyword in str(message).lower()

    return filter(contient_mot_cle, logs)


# ============================================================
# 9. FONCTION PRINCIPALE : PIPELINE DE FILTRAGE
# ============================================================

def smart_filter(
    records: Iterable[Any],
    levels: set[str] | None = None,
    ip_blacklist: set[str] | None = None,
    excluded_users: set[str] | None = None,
    protocols: set[str] | None = None,
    keyword: str | None = None
) -> Iterator[dict]:
    """
    Applique tous les critères de filtrage en un seul passage.

    Le traitement reste paresseux : les logs ne sont
    pas stockés intégralement en mémoire.
    """

    records = filter(valid_log, delete_empty_entries(records))

    selected_levels = VALID_LEVELS if levels is None else levels
    blocked_ips = set() if ip_blacklist is None else ip_blacklist
    blocked_users = set() if excluded_users is None else excluded_users
    selected_protocols = VALID_PROTOCOLS if protocols is None else protocols
    normalized_keyword = keyword.lower() if keyword else None

    def matches(log: dict) -> bool:
        if log["level"] not in selected_levels:
            return False
        if log["connection"][0] in blocked_ips:
            return False
        if log["user"] in blocked_users:
            return False
        if log["connection"][2] not in selected_protocols:
            return False

        if normalized_keyword is None:
            return True

        payload = log["payload"]
        message = payload.get("message", "") if isinstance(payload, dict) else payload
        return normalized_keyword in str(message).lower()

    return filter(matches, records)
