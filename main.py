from log_engine.ingestion import read_logs, read_logs_from_directory

# path=""
#
# for line in read_logs(path):
#    print(line)

for line in read_logs_from_directory("logs"):
    print(line)

# affichage du nombre de lignes lues
print(sum(1 for _ in read_logs_from_directory("logs")))