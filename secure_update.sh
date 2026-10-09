#!/bin/bash
# Watchtower updater - FAIL CLOSED (A15).
#
# The earlier version of this script printed "Signature Verified" and
# "Payload is authentic" without checking anything. That is false assurance,
# so it now refuses to run until a real signed-manifest check exists.
#
# Update the safe way instead (exact commit, no install scripts):
#   ./start.sh is stopped first, then:
#   git fetch origin
#   git checkout --detach <EXACT_REVIEWED_SHA>
#   npm ci --ignore-scripts --prefix backend
#   npm ci --ignore-scripts --prefix frontend
#   .venv/bin/pip install --require-hashes -r requirements.txt
#   then restart the service.
echo "[Watchtower Secure Updater] REFUSED: signed-update verification is not implemented." >&2
echo "Use the exact-SHA git procedure documented at the top of this script." >&2
exit 2
