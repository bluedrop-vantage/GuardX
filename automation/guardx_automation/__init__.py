"""GuardX automation plane (spec §5).

Every module in this package writes proposals via `POST /v1/proposals` — never
approved policies directly. Invariant I3 holds by construction.
"""

__version__ = "0.1.0"
