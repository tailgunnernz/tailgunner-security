#!/usr/bin/env bash
# Sends a signed health check, the way the monitor will.
# Usage: dev/health.sh https://tailgunner.co.nz [extra curl args]
# The signing key is read from ../uptime-monitor/.dev.vars and never printed.
set -euo pipefail

url="${1:?usage: dev/health.sh <site url> [curl args]}"
shift
vars="${TG_HEALTH_VARS:-$HOME/Documents/Tailgunner/uptime-monitor/.dev.vars}"
host=$(php -r 'echo parse_url($argv[1], PHP_URL_HOST);' "$url")

# php prints two lines: the body, then its signature.
signed=$(TG_VARS="$vars" php -r '
foreach (file(getenv("TG_VARS")) as $line) {
	if (strpos($line, "TG_HEALTH_SIGNING_KEY=") === 0) { $sk = base64_decode(trim(substr($line, 22))); }
}
if (empty($sk)) { fwrite(STDERR, "no TG_HEALTH_SIGNING_KEY\n"); exit(1); }
$body = json_encode(["host" => $argv[1], "ts" => (int) floor(microtime(true) * 1000)]);
echo $body, "\n", base64_encode(sodium_crypto_sign_detached($body, $sk)), "\n";
' "$host")

body=$(sed -n 1p <<<"$signed")
sig=$(sed -n 2p <<<"$signed")

curl -sS -X POST "${url%/}/?tailgunner-health" \
	-H 'Content-Type: application/json' \
	-H "X-Tailgunner-Signature: $sig" \
	--data-binary "$body" \
	-w '\nHTTP %{http_code}\n' "$@"
