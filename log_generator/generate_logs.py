import json
import random
import time
from datetime import datetime, timedelta

# Configuration du fichier de sortie
OUTPUT_FILE = "huge_system_logs_5.log"
TOTAL_LINES = 50_000  # Modifiez ici pour ajuster le nombre de lignes (ex: 2 à 5 millions)
BATCH_SIZE = 50_000      # Écriture par blocs pour optimiser les I/O disque

# Jeux de données pour la génération
IP_POOL = [f"192.168.1.{i}" for i in range(1, 100)] + [f"10.0.0.{i}" for i in range(1, 50)]
BLACKLISTED_IPS = ["192.168.1.66", "10.0.0.99", "172.16.0.4"] # Pour tester le Module 3 (frozenset)
ATTACKER_IP = "192.168.1.200" # IP dédiée à la simulation d'attaque Brute-Force

USERNAMES = ["admin", "alice", "bob", "charlie", "david", "guest", "service_account"]
LOG_LEVELS = ["INFO", "WARNING", "ERROR", "CRITICAL"]
LEVEL_WEIGHTS = [0.70, 0.18, 0.10, 0.02]  # Répartition réaliste des logs

MESSAGES_TEMPLATES = [
    "User authentication successful",
    "Failed password attempt for user",
    "Connection timed out after 3000ms",
    "Database connection pool exhausted",
    "File access granted to resource",
    "Unauthorized access attempt detected"
]

def generate_log_line(timestamp: str, corrupt_rate: float = 0.005) -> str:
    """
    Génère une ligne de log sous un format structuré ou semi-structuré.
    Injecte un faible pourcentage de lignes corrompues/malformées (ex: 0.5%).
    """
    
    # --- INJECTION DE LIGNES CORROMPUES ---
    if random.random() < corrupt_rate:
        corrupt_types = [
            "",                                      # Ligne vide (pour tester filter(None, ...))
            "   \n",                                 # Uniquement des espaces / saut de ligne
            "CORRUPTED_DATA_NULL_BYTES_\x00\x00\x00",# Octets nuls ou binaire invalide
            "2026-11-05 ERROR 192.168.1.1",          # Tronquée (manque des champs essentiels)
            '{"level": "ERROR", "ip": ',             # JSON invalide / mal formé
            "2026-99-99 99:99:99 INVALID_TIMESTAMP", # Horodatage absurde
        ]
        return random.choice(corrupt_types)

    # --- NORMALE : SIMULATION D'ATTAQUE (1%) ---
    if random.random() < 0.01:
        ip = ATTACKER_IP
        user = "admin"
        level = "ERROR"
        msg = "Failed password attempt for user"
    else:
        ip = random.choice(IP_POOL + BLACKLISTED_IPS)
        user = random.choice(USERNAMES)
        level = random.choices(LOG_LEVELS, weights=LEVEL_WEIGHTS)[0]
        msg = random.choice(MESSAGES_TEMPLATES)

    port = random.randint(1024, 65535)
    proto = random.choice(["TCP", "UDP"])

    # --- NORMALE : VARIABILITÉ DE FORMAT ---
    format_type = random.choices(["json", "kv", "raw"], weights=[0.6, 0.3, 0.1])[0]

    if format_type == "json":
        payload = {
            "timestamp": timestamp,
            "level": level,
            "ip": ip,
            "port": port,
            "protocol": proto,
            "user": user,
            "message": msg
        }
        return json.dumps(payload)
    
    elif format_type == "kv":
        return f"{timestamp} | LEVEL={level} | CONNECTION=({ip},{port},{proto}) | USER={user} | MSG=\"{msg}\""
    
    else:
        return f"{timestamp} {level} {ip}:{port} [{user}] - {msg}"

def generate_huge_log_file(filename: str, total_lines: int):
    """Génère le fichier de logs par lots (buffers) optimisés."""
    print(f"Début de la génération de {total_lines:,} lignes dans '{filename}'...")
    start_time = time.time()
    
    current_date = datetime.now() - timedelta(days=7) # Commence il y a 7 jours
    time_increment = timedelta(seconds=0.2) # ~5 logs par seconde

    written_lines = 0
    buffer = []

    with open(filename, "w", encoding="utf-8") as f:
        for i in range(1, total_lines + 1):
            current_date += time_increment
            ts_str = current_date.strftime("%Y-%m-%d %H:%M:%S")
            
            line = generate_log_line(ts_str)
            buffer.append(line + "\n")

            # Écriture par blocs pour ne pas faire chauffer l'I/O ni charger la RAM
            if i % BATCH_SIZE == 0:
                f.writelines(buffer)
                buffer.clear()
                written_lines = i
                print(f"Progression : {written_lines:,} / {total_lines:,} lignes ({(written_lines/total_lines)*100:.1f}%)")

        # Écriture des lignes restantes
        if buffer:
            f.writelines(buffer)

    elapsed = time.time() - start_time
    print(f"Terminé en {elapsed:.2f} secondes ! Fichier créé : {filename}")


if __name__ == "__main__":
    generate_huge_log_file(OUTPUT_FILE, TOTAL_LINES)