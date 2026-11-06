"""Print records matching manually configured filter conditions."""

from log_engine.ingestion import read_logs_from_directory
from log_engine.parsing import parse_logs
from log_transformation.filter import smart_filter


RECORDS = list(parse_logs(read_logs_from_directory("logs")))

# Edit these options to inspect different records. Remove an option to disable it.
FILTER_OPTIONS = {
    "levels": {"ERROR"},
    "ip_blacklist": {"192.168.1.63"},
    "excluded_users": {"bob"},
    "protocols": {"UDP"},
    "keyword": "failed",
}


def main() -> None:
    matching_records = smart_filter(RECORDS, **FILTER_OPTIONS)
    count = 0

    for count, record in enumerate(matching_records, start=1):
        print(f"{count}: {record}")

    print(f"\nTotal matching records: {count}")


if __name__ == "__main__":
    main()
