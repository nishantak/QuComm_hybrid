from benchmark import BenchmarkRunner

def main():
    """
    Spp that runs benchmark suite
    """
    runner = BenchmarkRunner(
        message_size=1024,   # size of each test message (1 KB)
        runs=8,              # number of experiment runs per backend
        repetitions=100,     # number of messages per run (for throughput)
        log_dir="logs"       # directory for logs
    )
    results = runner.run()
    return results


if __name__ == "__main__":
    main()
