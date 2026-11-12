#!/usr/bin/env bash
# Start a throwaway Elasticsearch container for the live Elasticsearch
# reference, and print the environment run.py needs:
#
#   eval "$(bash scripts/engine/oracles/elasticsearch/start.sh 9.3.0)"
#   python3 scripts/engine/oracles/elasticsearch/run.py --language eql DIR
#
# The argument is an image tag (default 9.3.0). The image is the official one,
# pulled through mirror.gcr.io because docker.elastic.co is not reachable from
# every CI runner; set ES_IMAGE to use another registry. Security is off and
# the licence is basic (EQL and ES|QL are basic features). The port is bound
# to 127.0.0.1 only. Set ES_PORT to run two versions side by side. Disk
# watermarks are off: the fixture indices hold no documents, and a nearly full
# CI disk would otherwise leave their shards unassigned.
set -euo pipefail
version="${1:-9.3.0}"
image="${ES_IMAGE:-mirror.gcr.io/library/elasticsearch}:$version"
port="${ES_PORT:-9200}"
name="opentide-es-oracle-$port"

# A registry answers a burst of pulls with 429 Too Many Requests: pull with
# backoff first, so a rate limit is a wait rather than a failed job.
# ES_PULL_DELAY is the first wait in seconds (doubled after each failure).
delay="${ES_PULL_DELAY:-15}"
for attempt in 1 2 3 4; do
  if docker pull --quiet "$image" >&2; then
    break
  fi
  if [ "$attempt" -eq 4 ]; then
    echo "could not pull $image after $attempt attempts" >&2
    exit 1
  fi
  echo "pull $attempt of $image failed; retrying in ${delay}s" >&2
  sleep "$delay"
  delay=$((delay * 2))
done

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p "127.0.0.1:$port:9200" \
  -e discovery.type=single-node \
  -e xpack.security.enabled=false \
  -e xpack.license.self_generated.type=basic \
  -e xpack.ml.enabled=false \
  -e cluster.routing.allocation.disk.threshold_enabled=false \
  -e ES_JAVA_OPTS="-Xms1g -Xmx1g" \
  "$image" >&2
echo "started $name from $image; run.py waits for cluster health yellow" >&2
echo "export ES_URL=http://127.0.0.1:$port"
