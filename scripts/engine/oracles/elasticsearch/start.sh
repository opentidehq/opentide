#!/usr/bin/env bash
# Start a throwaway Elasticsearch container for the live Elasticsearch
# reference, and print the environment run.py needs:
#
#   eval "$(bash scripts/engine/oracles/elasticsearch/start.sh 9.3.0)"
#   python3 scripts/engine/oracles/elasticsearch/run.py --language eql DIR
#
# The argument is an image tag (default 9.3.0). The image is the official one,
# pulled through mirror.gcr.io first because docker.elastic.co is not
# reachable from every CI runner, then from Docker Hub and docker.elastic.co
# when a registry refuses (mirror.gcr.io answers with a quota error when its
# per-minute limit is spent); set ES_IMAGE to use one registry only. Security is off and
# the licence is basic (EQL and ES|QL are basic features). The port is bound
# to 127.0.0.1 only. Set ES_PORT to run two versions side by side. Disk
# watermarks are off: the fixture indices hold no documents, and a nearly full
# CI disk would otherwise leave their shards unassigned.
set -euo pipefail
version="${1:-9.3.0}"
if [ -n "${ES_IMAGE:-}" ]; then
  images=("$ES_IMAGE:$version")
else
  images=(
    "mirror.gcr.io/library/elasticsearch:$version"
    "docker.io/library/elasticsearch:$version"
    "docker.elastic.co/elasticsearch/elasticsearch:$version"
  )
fi
port="${ES_PORT:-9200}"
name="opentide-es-oracle-$port"

# A registry answers a burst of pulls with 429 Too Many Requests or a quota
# error: each registry is tried with backoff, then the next one, so a rate
# limit is a wait or a detour rather than a failed job. ES_PULL_DELAY is the
# first wait in seconds (doubled after each failure); ES_PULL_ATTEMPTS is the
# number of tries per registry.
attempts="${ES_PULL_ATTEMPTS:-3}"
image=""
for candidate in "${images[@]}"; do
  delay="${ES_PULL_DELAY:-15}"
  for attempt in $(seq 1 "$attempts"); do
    if docker pull --quiet "$candidate" >&2; then
      image="$candidate"
      break 2
    fi
    if [ "$attempt" -lt "$attempts" ]; then
      echo "pull $attempt of $candidate failed; retrying in ${delay}s" >&2
      sleep "$delay"
      delay=$((delay * 2))
    else
      echo "pull $attempt of $candidate failed; trying the next registry" >&2
    fi
  done
done
if [ -z "$image" ]; then
  echo "could not pull elasticsearch:$version from ${images[*]}" >&2
  exit 1
fi

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
