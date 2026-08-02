#!/usr/bin/env bash
# Parse arguments
URL=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -u|--url)
      URL="$2"
      shift 2
      ;;
    *)
      URL="$1"
      shift
      ;;
  esac
done

if [ -z "$URL" ]; then
  echo "Error: No URL/domain provided"
  exit 1
fi

# Extract host/domain if it's a full URL
DOMAIN="$URL"
if [[ "$URL" == http* ]]; then
  DOMAIN=$(echo "$URL" | awk -F/ '{print $3}')
fi

echo "$DOMAIN" > /tmp/targets.txt
python3 /opt/gittools/Finder/gitfinder.py -i /tmp/targets.txt
