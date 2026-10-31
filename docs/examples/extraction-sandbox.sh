#!/bin/sh
# Example sandbox wrapper for attachment extraction (ADR 0019); configure it as
# extraction.sandbox. Shem runs: extraction-sandbox.sh <java worker command...>
# with an empty environment, so every path below is literal.
#
# The worker gets its own network namespace (no network at all, not even the host's
# loopback) and a mount namespace in which the Shem data directory is covered by an
# empty tmpfs. The worker therefore cannot reach mailbox, key, queue, or ACME files.
# Shem's startup probe verifies both properties and refuses to start otherwise.
#
# Requirements: util-linux unshare, and either root or unprivileged user namespaces
# (kernel.unprivileged_userns_clone=1). Run the server as its own non-root user; with
# --map-root-user the worker is "root" only inside its namespace.
#
# Equivalent with bubblewrap:
#   exec bwrap --unshare-all --die-with-parent --ro-bind / / --dev /dev --proc /proc \
#        --tmpfs /var/lib/shem/data --bind /run/shem-scratch /run/shem-scratch "$@"
set -eu
DATA_DIR=/var/lib/shem/data
exec /usr/bin/unshare --user --map-root-user --net --mount --propagation private \
  /bin/sh -c 'mount -t tmpfs -o size=1m tmpfs "$0" && exec "$@"' "$DATA_DIR" "$@"
