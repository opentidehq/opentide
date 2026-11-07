#!/usr/bin/env bash
# Start a throwaway Splunk Enterprise container for the SPL oracle on this
# machine, and print the environment the oracle needs:
#
#   eval "$(bash scripts/oracles/splunk/start.sh)"
#   bash scripts/ci-oracle.sh spl
#
# Running this accepts the Splunk General Terms for the container, exactly as
# .github/workflows/oracle.yml does. The port is bound to 127.0.0.1 only.
set -euo pipefail
image="${SPLUNK_IMAGE:-splunk/splunk:10.6.1}"
name=opentide-splunk-oracle
password="opentide-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p 127.0.0.1:8089:8089 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD="$password" \
  "$image" >&2
echo "started $name from $image; oracle.py waits for splunkd to answer" >&2
echo "export SPLUNK_URL=https://127.0.0.1:8089 SPLUNK_PASSWORD=$password"
