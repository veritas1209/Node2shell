#!/bin/sh
set -eu

mode="${1:-vulnerable}"
case "$mode" in
  vulnerable)
    tag='24.22.0'
    image_digest='sha256:925de64a85319052d6971ae81ef2417da956e8a3a2c4a0fac732327970f017f5'
    node_sha256='67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c'
    ;;
  patched)
    tag='24.22.1'
    image_digest='sha256:6449e19d8184d84062525b6a7524def03146c2cb04a7f08b076680d0e8e4240a'
    node_sha256='e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb'
    ;;
  *)
    echo 'usage: ./lab/run.sh [vulnerable|patched]' >&2
    exit 64
    ;;
esac

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
context="$root/lab/express-nonce-proof"
image="node2shell-nonce-local:$tag"
container="node2shell-nonce-lab-$$"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build --platform linux/amd64 \
  --build-arg "NODE_IMAGE=mirror.gcr.io/library/node@$image_digest" \
  --tag "$image" \
  --file "$context/Dockerfile" \
  "$context"

docker run --platform linux/amd64 --detach \
  --name "$container" \
  --label org.openai.node2shell-lab=true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1.0 \
  --publish 127.0.0.1:3000:3000 \
  "$image" >/dev/null

actual_sha256="$(docker exec "$container" sha256sum /usr/local/bin/node | awk '{print $1}')"
if [ "$actual_sha256" != "$node_sha256" ]; then
  echo "Node binary fingerprint mismatch: $actual_sha256" >&2
  exit 1
fi

if [ "$mode" = patched ]; then
  python3 "$root/poc/node2shell_lab.py" --expect patched --timeout 30
  exit $?
fi
python3 "$root/poc/node2shell_lab.py" --attempts 32 --timeout 30
