import time
from core.icmp_core import probe_host, DEFAULT_TTL

def run_ping(target, count=4):
    """
    Person 2's Logic: Runs a ping loop and prints statistics.
    """
    results = []
    print(f"\n--- Pinging {target} with 64 bytes of data ---")

    for i in range(1, count + 1):
        # 1. CALL Person 1's engine
        # This function handles the socket, sending, and receiving [cite: 118]
        result = probe_host(target, ttl=DEFAULT_TTL, sequence=i)
        results.append(result)

        if result.received:
            # result.rtt_ms was calculated by Person 1's engine [cite: 128]
            print(f"Reply from {result.responding_host}: bytes=64 seq={i} time={result.rtt_ms:.3f}ms")
        else:
            print(f"Request timed out for seq {i}")

        # Standard ping delay of 1 second between probes
        if i < count:
            time.sleep(1)

    # 2. CALCULATE STATISTICS (Your core responsibility)
    print_stats(target, results)

def print_stats(target, results):
    total = len(results)
    received = [r for r in results if r.received]
    lost = total - len(received)
    loss_percent = (lost / total) * 100

    print(f"\n--- {target} ping statistics ---")
    print(f"{total} packets transmitted, {len(received)} received, {loss_percent:.1f}% packet loss")

    if received:
        rtts = [r.rtt_ms for r in received]
        avg_rtt = sum(rtts) / len(rtts)
        print(f"rtt min/avg/max = {min(rtts):.3f}/{avg_rtt:.3f}/{max(rtts):.3f} ms")

if __name__ == "__main__":
    # You can change the target here for testing
    run_ping("8.8.8.8", count=4)
