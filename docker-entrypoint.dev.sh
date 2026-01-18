#!/bin/sh
set -e

# If arguments passed, run them directly (e.g., docker compose run api make test)
if [ $# -gt 0 ]; then
    exec "$@"
fi

# Default behavior: build and run the API
make build

if [ -f config.yml ]; then
    exec ./bin/cservice-api -config config.yml
else
    exec ./bin/cservice-api
fi
