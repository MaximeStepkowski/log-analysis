def read_logs(path):
    """Read a log file line by line (generator)"""
    with open(path, encoding="utf-8") as file:
        for line in file:
            yield line.rstrip("\n")
