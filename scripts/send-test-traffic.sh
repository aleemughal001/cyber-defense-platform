#!/usr/bin/env bash
set -e

echo "Sending normal traffic..."
curl -A "Mozilla/5.0" http://example.com >/dev/null 2>&1 || true

echo "Sending suspicious sqlmap traffic..."
curl -A "sqlmap/1.7.0" http://example.com/test?id=1 >/dev/null 2>&1 || true

echo "Sending suspicious command injection style traffic..."
curl "http://example.com/cgi-bin/test?/bin/sh" >/dev/null 2>&1 || true

echo "Done."
