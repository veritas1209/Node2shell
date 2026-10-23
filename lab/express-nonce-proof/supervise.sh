#!/bin/sh
set -eu

while :; do
  N2S_PROOF="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  export N2S_PROOF
  if [ "${N2S_DISABLE_ASLR:-0}" = 1 ]; then
    setarch x86_64 -R node /app/server.js || true
  else
    node /app/server.js || true
  fi
  sleep 0.1
done
