#!/bin/sh
# healthcheck-internal.sh

# This script checks if the main log-processor script is running.
if pgrep -f "/scripts/log-processor.sh"; then
  echo "Healthcheck OK: log-processor.sh is running."
  exit 0
else
  echo "Healthcheck FAILED: log-processor.sh is not running."
  exit 1
fi
