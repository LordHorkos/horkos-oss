# rate-limiter

A small, thread-safe token-bucket rate limiter with no dependencies. Enforces
both a **per-second rate** and a **global request cap** in one object — useful
when you want to throttle outbound requests *and* guarantee a hard ceiling on
the total.

## Usage

```python
from rate_limiter import TokenBucket

# refill 0.3 tokens/sec, allow short bursts of 3, never exceed 500 total
tb = TokenBucket(rate=0.3, burst=3, max_requests=500)

for item in work:
    if not tb.acquire(max_wait=30.0):
        break          # global cap hit, or no token within max_wait
    do_request(item)
```

- `acquire(max_wait)` consumes one token, blocking up to `max_wait` seconds for
  one to refill. Returns `False` if the global cap is reached or the wait would
  exceed `max_wait`; `True` once a token is taken.
- `rate` — tokens added per second.
- `burst` — bucket capacity; the most that can be spent back-to-back.
- `max_requests` — hard lifetime ceiling, independent of the rate.
- `.consumed` — tokens taken so far. `.exhausted` — whether the global cap is hit.

Refills are computed from `time.monotonic()` deltas, so it's robust to wall-clock
changes and holds under concurrent `acquire()` from multiple threads.

## Tests

```bash
python3 test_rate_limiter.py     # exit 0 = pass
```
