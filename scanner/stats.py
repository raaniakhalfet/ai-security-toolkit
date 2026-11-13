"""Small statistics helpers (no extra libraries needed).

With only a few dozen runs, a rate such as "0 out of 36" does not mean the true rate
is exactly 0%. The Wilson score interval gives a range the true rate probably lies in.
"""
from math import sqrt


def wilson(successes, n, z=1.96):
    """95% Wilson score interval for a rate. Returns (low, high) as fractions 0..1."""
    if n == 0:
        return 0.0, 1.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def fmt_ci(successes, n):
    """Text like '0-10%' for a 95% interval."""
    lo, hi = wilson(successes, n)
    return f"{100 * lo:.0f}-{100 * hi:.0f}%"


def overlaps(a, b):
    """True if two (low, high) intervals overlap, so the difference may be due to chance."""
    return a[0] <= b[1] and b[0] <= a[1]


if __name__ == "__main__":
    for s, n in [(0, 36), (0, 60), (12, 36), (26, 60), (7, 36), (1, 30), (0, 100)]:
        print(f"{s}/{n}: {100 * s / n:.0f}%  95% CI {fmt_ci(s, n)}")
