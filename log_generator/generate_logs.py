import json
import argparse
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

# Output file configuration
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "logs"
TOTAL_LINES = 1_000_000  # Requested number of lines
BATCH_SIZE = 50_000      # Batch writes to optimize disk I/O
IO_BUFFER_SIZE = 1024 * 1024
DEFAULT_LOG_RATE = 20.0
MIN_LOG_RATE = 10.0
MAX_LOG_RATE = 30.0


def get_output_file(
    file_number: int = 1,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Path:
    """Build the path of a numbered log file."""
    if file_number < 1:
        raise ValueError("Le numéro du fichier doit être supérieur ou égal à 1.")

    return Path(output_dir) / f"logs_file_http_{file_number}.log"


# --- HTTP DATASETS ---
IP_POOL = (
    [
        *[f"192.168.1.{i}" for i in range(1, 100)],
        *[f"10.0.0.{i}" for i in range(1, 50)],
        *[f"172.16.0.{i}" for i in range(1, 30)],
    ]
)
BLACKLISTED_IPS = ["192.168.1.66", "10.0.0.99", "172.16.0.4"]
ALL_IPS = IP_POOL + BLACKLISTED_IPS
# IP dedicated to simulating a web attack (brute force / fuzzing)
ATTACKER_IP = "192.168.1.200"

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
METHOD_WEIGHTS = [0.65, 0.20, 0.08, 0.04, 0.02, 0.01]
WEIGHTED_METHODS = [
    method
    for method, weight in zip(HTTP_METHODS, METHOD_WEIGHTS)
    for _ in range(round(weight * 100))
]

STATUS_CODES = [200, 201, 301, 304, 400, 401, 403, 404, 500, 502, 503]
STATUS_WEIGHTS = [
    0.70, 0.08, 0.05, 0.05, 0.03, 0.02,
    0.02, 0.03, 0.01, 0.005, 0.005,
]
WEIGHTED_STATUS_CODES = [
    status
    for status, weight in zip(STATUS_CODES, STATUS_WEIGHTS)
    for _ in range(round(weight * 1000))
]

ENDPOINTS = [
    "/", "/index.html", "/api/v1/auth/login", "/api/v1/users",
    "/api/v1/products", "/cart/checkout", "/static/js/main.js",
    "/static/css/styles.css", "/images/logo.png", "/admin/dashboard",
    "/api/v1/orders"
]

USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
        "Safari/605.1.15"
    ),
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Python-urllib/3.10",
    "curl/7.68.0",
    "PostmanRuntime/7.32.3"
]

REFERERS = [
    "-",
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://example.com/login",
    "https://example.com/products"
]
CLIENT_PORT_MIN = 1024
CLIENT_PORT_MAX = 65535
FORMAT_TYPES = ["combined", "json", "kv"]
FORMAT_WEIGHTS = [0.6, 0.3, 0.1]
WEIGHTED_FORMAT_TYPES = [
    format_type
    for format_type, weight in zip(FORMAT_TYPES, FORMAT_WEIGHTS)
    for _ in range(round(weight * 10))
]


def generate_http_log_line(
    timestamp_dt: datetime,
    corrupt_rate: float = 0.005,
    empty_rate: float = 0.003,
) -> str:
    """
    Generate an HTTP log line.
    Inject:
    - Empty lines ("") or whitespace-only lines ("   ").
    - Corrupted or malformed lines.
    - Normal HTTP requests or suspicious behavior.
    """

    # --- EMPTY OR WHITESPACE LINE INJECTION ---
    if random.random() < empty_rate:
        empty_types = [
            "",                                      # Completely empty line
            " ",                                     # Un seul espace
            "           ",                           # Multiples espaces
            "\t\t   "  # Mixture of tabs and spaces
        ]
        return random.choice(empty_types)

    # --- CORRUPTED LINE INJECTION ---
    if random.random() < corrupt_rate:
        corrupt_types = [
            "CORRUPTED_DATA_NULL_BYTES_\x00\x00\x00",
            # Truncated (missing status and bytes)
            "192.168.1.1 - - [05/Nov/2026:12:00:00 +0000] \"GET / HTTP/1.1\"",
            '{"timestamp": "2026-11-05T12:00:00Z", "ip": ',
            # JSON invalide
            "2026-99-99 99:99:99 HTTP INVALID_TIMESTAMP",
            # Format brut sans IP/Date
            "GET /admin/login HTTP/1.1 401 512"
        ]
        return random.choice(corrupt_types)

    # --- ATTACK SIMULATION (1%) ---
    if random.random() < 0.01:
        ip = ATTACKER_IP
        method = "POST"
        endpoint = "/admin/login"
        status = random.choice([401, 403])
        bytes_sent = random.randint(150, 300)
        user_agent = "Python-urllib/3.10"
        referer = "-"
        response_time_ms = random.randint(10, 50)
    else:
        ip = random.choice(ALL_IPS)
        method = random.choice(WEIGHTED_METHODS)
        endpoint = random.choice(ENDPOINTS)
        status = random.choice(WEIGHTED_STATUS_CODES)
        bytes_sent = random.randint(
            200, 15000) if status == 200 else random.randint(0, 500)
        user_agent = random.choice(USER_AGENTS)
        referer = random.choice(REFERERS)
        response_time_ms = random.randint(5, 1200)

    client_port = random.randint(CLIENT_PORT_MIN, CLIENT_PORT_MAX)

    http_version = "HTTP/1.1"

    # --- FORMAT VARIATION ---
    format_type = random.choice(WEIGHTED_FORMAT_TYPES)

    if format_type == "combined":
        # Enriched combined format: IP:PORT - - [Date] "METHOD URL PROTOCOL" STATUS
        # BYTES "REFERER" "USER-AGENT"
        ts_combined = timestamp_dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (
            f'{ip}:{client_port} - - [{ts_combined}] '
            f'"{method} {endpoint} {http_version}" {status} '
            f'{bytes_sent} "{referer}" "{user_agent}"'
        )

    elif format_type == "json":
        # Structured JSON format for Kibana / Loki
        payload = {
            "timestamp": timestamp_dt.isoformat() + "Z",
            "remote_addr": ip,
            "remote_port": client_port,
            "request_method": method,
            "request_uri": endpoint,
            "status": status,
            "body_bytes_sent": bytes_sent,
            "request_time_ms": response_time_ms,
            "http_referrer": referer,
            "http_user_agent": user_agent
        }
        return json.dumps(payload)

    else:
        # Format Key-Value
        ts_kv = timestamp_dt.strftime("%Y-%m-%d %H:%M:%S")
        return (
            f'time="{ts_kv}" client_ip={ip} client_port={client_port} '
            f'method={method} path="{endpoint}" status={status} '
            f'bytes={bytes_sent} duration_ms={response_time_ms} '
            f'agent="{user_agent}"'
        )


def random_start_datetime() -> datetime:
    """Return a random start time within the last 30 days."""
    return datetime.now() - timedelta(days=random.uniform(7, 30))


def random_log_rate() -> float:
    """Return a realistic random log rate per second."""
    return random.uniform(MIN_LOG_RATE, MAX_LOG_RATE)


def generate_huge_log_file(
    filename: str | Path,
    total_lines: int,
    max_lines_per_second: int | None = None,
    batch_size: int = BATCH_SIZE,
    start_datetime: datetime | None = None,
    log_rate: float = DEFAULT_LOG_RATE,
) -> datetime:
    """Generate a file and return the timestamp of its last line."""
    if total_lines < 0:
        raise ValueError("Le nombre de lignes doit être supérieur ou égal à 0.")
    if max_lines_per_second is not None and max_lines_per_second < 1:
        raise ValueError("La cadence maximale doit être supérieure ou égale à 1.")
    if batch_size < 1:
        raise ValueError("La taille de lot doit être supérieure ou égale à 1.")
    if log_rate <= 0:
        raise ValueError("Le débit de logs doit être supérieur à 0.")

    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Début de la génération de {total_lines:,} logs HTTP dans '{filename}'...")
    start_time = time.time()

    current_date = start_datetime or random_start_datetime()
    time_increment = timedelta(seconds=1 / log_rate)

    written_lines = 0
    buffer = []

    with open(output_path, "w", encoding="utf-8", buffering=IO_BUFFER_SIZE) as f:
        for i in range(1, total_lines + 1):
            current_date += time_increment

            line = generate_http_log_line(current_date)
            buffer.append(line + "\n")

            # Write in batches to limit I/O and RAM impact.
            if i % batch_size == 0:
                f.writelines(buffer)
                buffer.clear()
                written_lines = i
                progress = written_lines / total_lines * 100
                print(
                    f"Progression : {written_lines:,} / {total_lines:,} "
                    f"lignes ({progress:.1f}%)"
                )
                if max_lines_per_second is not None:
                    target_elapsed = written_lines / max_lines_per_second
                    time.sleep(max(0, target_elapsed - (time.time() - start_time)))

        # Write the remaining buffer.
        if buffer:
            f.writelines(buffer)

    elapsed = time.time() - start_time
    print(f"Terminé en {elapsed:.2f} secondes ! Fichier créé : {filename}")
    return current_date


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Génère un fichier de logs HTTP.")
    parser.add_argument(
        "--number",
        "-n",
        type=int,
        default=1,
        help="Numéro du fichier (défaut : 1).",
    )
    parser.add_argument(
        "--lines",
        "-l",
        type=int,
        default=TOTAL_LINES,
        help=f"Nombre de lignes (défaut : {TOTAL_LINES}).",
    )
    parser.add_argument(
        "--max-rate",
        type=int,
        default=None,
        help=(
            "Limite le nombre de lignes générées par seconde "
            "pour réduire la charge CPU."
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=BATCH_SIZE,
        help=f"Nombre de lignes écrites par lot (défaut : {BATCH_SIZE}).",
    )
    parser.add_argument(
        "--log-rate",
        type=float,
        default=DEFAULT_LOG_RATE,
        help=(
            "Débit utilisé pour les timestamps (logs/s, "
            f"défaut : {DEFAULT_LOG_RATE:g})."
        ),
    )
    arguments = parser.parse_args()

    try:
        generate_huge_log_file(
            get_output_file(arguments.number),
            arguments.lines,
            arguments.max_rate,
            arguments.batch_size,
            log_rate=arguments.log_rate,
        )
    except ValueError as error:
        raise SystemExit(f"Erreur : {error}") from error
