from log_engine.ingestion import read_logs

for line in read_logs(path):
    print(line)