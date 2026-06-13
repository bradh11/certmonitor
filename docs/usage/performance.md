# Performance Tips

CertMonitor is built to stay out of your way when you're checking a lot of hosts. The good news up front: the dominant cost of a check is network I/O, not parsing. The actual certificate parsing happens in Rust, and CertMonitor releases the GIL while that work runs, so it plays nicely with async code and threads. That means the biggest wins come from overlapping the network waits, not from optimizing the parsing.

A couple of habits go a long way:

- Use the context manager so connections are opened and closed promptly.
- For batch testing, lean on Python's `asyncio` and `asyncio.to_thread` to run checks in parallel (see `test.py` for an example).

## Asynchronous Usage for Performance

So why does async help so much here? Because each check spends most of its time waiting on the network. While one host is mid-handshake, your program could be talking to another. CertMonitor's context manager is thread-safe, and it releases the GIL during the Rust calls, so you can fan many checks out at once and let them overlap.

Here's a real-world example using `asyncio` and `asyncio.to_thread`:

```python
import asyncio
import json
import time
from certmonitor import CertMonitor

start_time = time.time()
total_time = 0
num_tests = 0
print_lock = asyncio.Lock()

async def test_certinfo_async(hostname, port: int = 443):
    global total_time, num_tests
    start = time.time()
    validators = [
        "subject_alt_names",
        "weak_cipher",
        "tls_version",
    ]
    def run_certmonitor():
        lines = []
        with CertMonitor(host=hostname, port=port, enabled_validators=validators) as monitor:
            lines.append(f"Testing {hostname}:{port}")
            cert_details = monitor.get_cert_info()
            lines.append(json.dumps(cert_details, indent=2))
            verification_results = monitor.validate(
                validator_args={
                    "subject_alt_names": {
                        "alternate_names": [
                            "www.example.com",
                            "cisco.com",
                            "test.google.com",
                            "8.8.4.4",
                            "test.badssl.com",
                        ]
                    }
                }
            )
            lines.append(json.dumps(verification_results, indent=2))
            cipher_info = monitor.get_cipher_info()
            lines.append(json.dumps(cipher_info, indent=2))
        return "\n".join(lines)
    output = await asyncio.to_thread(run_certmonitor)
    end = time.time()
    elapsed = end - start
    total_time += elapsed
    num_tests += 1
    chunk = "\n" + "=" * 50 + "\n" + f"{output}\n" + f"Test completed in {elapsed:.2f} seconds\n" + "=" * 50 + "\n"
    async with print_lock:
        print(chunk)
    return elapsed

async def main():
    hosts = [
        ("expired.badssl.com", 443),
        ("8.8.8.8", 443),
        ("example.com", 443),
        ("tls-v1-0.badssl.com", 1010),
        ("tls-v1-1.badssl.com", 1011),
        ("tls-v1-2.badssl.com", 1012),
    ]
    tasks = [test_certinfo_async(host, port) for (host, port) in hosts]
    for task in asyncio.as_completed(tasks):
        try:
            await task
        except Exception as e:
            async with print_lock:
                print("\n" + "=" * 50 + "\n")
                print(f"Test raised an exception: {e}")
                print("=" * 50 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
    end_time = time.time()
    elapsed_time = end_time - start_time
    average_time = total_time / num_tests if num_tests else 0
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
    print(f"Average time per test: {average_time:.2f} seconds")
```

Notice the pattern: each host runs inside `asyncio.to_thread`, and `asyncio.as_completed` lets you process results as soon as they finish rather than waiting for the slowest host. That's what lets you test many hosts in parallel, maximizing throughput and minimizing total runtime.

!!! tip "Start with the network in mind"
    Since the network is the bottleneck, the lever that matters most is concurrency. Adding more parallel checks usually helps far more than anything you could tune in the parsing path.
