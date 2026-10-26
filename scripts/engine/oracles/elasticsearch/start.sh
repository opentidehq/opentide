#!/usr/bin/env bash
# Start a throwaway Elasticsearch container for the live Elasticsearch
# reference, and print the environment run.py needs:
#
#   eval "$(bash scripts/oracles/elasticsearch/start.sh 9.3.0)"
#   python3 scripts/oracles/elasticsearch/run.py --language eql DIR
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
