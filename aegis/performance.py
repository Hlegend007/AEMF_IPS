import os
import time
from dataclasses import dataclass

@dataclass
class PerformanceSample:
    cpu_percent: float
    memory_mb: float
    elapsed: float
    packets_processed: int

def sample_system(interval=0.1, packets_processed=0):
    try:
        import psutil
    except ImportError:
        return None
    proc = psutil.Process(os.getpid())
    cpu = proc.cpu_percent(interval=interval)
    memory = proc.memory_info().rss / (1024 * 1024)
    return PerformanceSample(cpu, memory, interval, packets_processed)

def run_processing_benchmark(monitor, packets=10000):
    """Synthetic packet-rate benchmark for the project's resource test."""
    from .models import Fragment
    start = time.perf_counter()
    for i in range(packets):
        key = ("10.0.0.1", 1000 + (i % 1000))
        monitor.process_fragment(
            key, "ICMP",
            Fragment(i, b"x", time.time()),
            "10.0.0.1", "02:00:00:00:00:02",
            complete=(i % 10 == 9),
        )
    elapsed = max(time.perf_counter() - start, 1e-9)
    sample = sample_system(0.05, packets)
    result = {
        "packets": packets,
        "elapsed_seconds": elapsed,
        "packets_per_second": packets / elapsed,
        "cpu_percent": sample.cpu_percent if sample else None,
        "memory_mb": sample.memory_mb if sample else None,
        "resource_metrics_available": sample is not None,
    }
    return result
