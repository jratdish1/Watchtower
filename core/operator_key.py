"""Fail closed when a client process has no private operator key."""
import os
import sys

FORBIDDEN = (
    "WATCHTOWER_DEFAULT_KEY",
    "YOUR_SECRET_API_KEY_HERE",
    "generate_a_secure_random_key_here",
)
MIN_LENGTH = 32


def require_operator_key(name="WATCHTOWER_API_KEY"):
    raw = os.environ.get(name)
    stripped = "" if raw is None else raw.strip()
    if raw is None or stripped == "" or stripped in FORBIDDEN or len(stripped) < MIN_LENGTH:
        sys.stderr.write(
            "[Watchtower] Refusing to start: "
            + name
            + " is unset, empty, a public placeholder, or shorter than 32 characters.\n"
        )
        raise SystemExit(1)
    # Return the stripped value: the value validated above is the value every
    # compare and x-api-key header uses (padded/CRLF env values no longer 401).
    return stripped
