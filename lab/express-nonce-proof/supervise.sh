#!/bin/sh
set -eu

while :; do
  N2S_PROOF="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  export N2S_PROOF
  node /app/server.js || true
  sleep 0.1
done
