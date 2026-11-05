from log_engine.ingestion import read_logs, read_logs_from_directory
from log_engine.parsing import parse_logs
# path=""
#
# for line in read_logs(path):
#    print(line)

for record in parse_logs(read_logs_from_directory("logs")):
    print(record)

# affichage du nombre de lignes lues
print(sum(1 for _ in read_logs_from_directory("logs")))