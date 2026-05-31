import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_PATHS = ["/", "/jobs", "/api/jobs", "/faq", "/guides"]


def fetch(base_url, path, timeout):
    url = base_url.rstrip("/") + path
    start = time.perf_counter()
    try:
        request = Request(url, headers={"User-Agent": "jobboard-load-test/1.0"})
        with urlopen(request, timeout=timeout) as response:
            response.read(2048)
            status = response.status
    except HTTPError as exc:
        status = exc.code
    except URLError:
        status = 0
    elapsed_ms = (time.perf_counter() - start) * 1000
    return {"url": url, "status": status, "elapsed_ms": elapsed_ms}


def main():
    parser = argparse.ArgumentParser(description="Lightweight local load test for JobBoard AI routes.")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000", help="Base URL to test.")
    parser.add_argument("--requests", type=int, default=50, help="Total requests to send.")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent workers.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds.")
    parser.add_argument("--path", action="append", dest="paths", help="Path to test. Can be repeated.")
    args = parser.parse_args()

    paths = args.paths or DEFAULT_PATHS
    scheduled_paths = [paths[index % len(paths)] for index in range(args.requests)]

    started = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(fetch, args.base_url, path, args.timeout) for path in scheduled_paths]
        for future in as_completed(futures):
            results.append(future.result())

    total_elapsed = time.perf_counter() - started
    latencies = [item["elapsed_ms"] for item in results]
    ok_count = sum(1 for item in results if 200 <= item["status"] < 400)
    failed = [item for item in results if not (200 <= item["status"] < 400)]

    print("JobBoard AI load test")
    print(f"Base URL: {args.base_url}")
    print(f"Requests: {len(results)}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Successful: {ok_count}")
    print(f"Failed: {len(failed)}")
    print(f"Total time: {total_elapsed:.2f}s")
    print(f"Requests/sec: {len(results) / total_elapsed:.2f}")
    print(f"Latency avg: {statistics.mean(latencies):.1f} ms")
    print(f"Latency p95: {statistics.quantiles(latencies, n=20)[18]:.1f} ms" if len(latencies) >= 20 else "Latency p95: n/a")
    print(f"Latency max: {max(latencies):.1f} ms")

    if failed:
        print("\nFailures:")
        for item in failed[:10]:
            print(f"- {item['status']} {item['url']} {item['elapsed_ms']:.1f} ms")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
