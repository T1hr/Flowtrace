"""Measure numbered offline replay of synthetic frames through the analysis pipeline."""
from dataclasses import replace
from pathlib import Path
from queue import Full, Queue
from threading import Thread
import time

from analysis_core import FlowTracker
from capture_file import read_pcap
from decode import decode
from diagnosis import Diagnostics


def replay(rate, seconds=3):
    with Path(__file__).with_name("demo.pcap").open("rb") as file:
        fixtures = list(read_pcap(file))
    queue = Queue(maxsize=1024)
    sent = rate * seconds
    dropped = 0
    processed = 0
    peak = 0
    tracker, diagnostic = FlowTracker(), Diagnostics()

    def analyze():
        nonlocal processed
        while (item := queue.get()) is not None:
            number, frame = item
            packet = decode(frame)
            diagnostic.accept(number, packet, tracker.update(packet), set())
            processed += 1

    consumer = Thread(target=analyze)
    wall, cpu = time.perf_counter(), time.process_time()
    consumer.start()
    for number in range(sent):
        due = wall + number / rate
        if number % 32 == 0:
            delay = due - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
        original = fixtures[number % len(fixtures)]
        stamp = fixtures[0].ns + number * 10**9 // rate
        try:
            queue.put_nowait((number, replace(original, ns=stamp)))
            peak = max(peak, queue.qsize())
        except Full:
            dropped += 1
    queue.put(None)
    consumer.join()
    elapsed = time.perf_counter() - wall
    assert sent == processed + dropped
    return (rate, sent, processed, dropped, peak, elapsed, processed / elapsed,
            (time.process_time() - cpu) / elapsed * 100)


if __name__ == "__main__":
    print("target_pps offered parsed queue_drops queue_peak wall_s processed_pps CPU_percent_one_core")
    for rate in (1000, 10000):
        print(" ".join(f"{x:.2f}" if isinstance(x, float) else str(x) for x in replay(rate)))


