#!/bin/sh
# Update SHA256SUM.txt
set -eu

cd "$(dirname -- "$0")"

find intel_bluetooth intel_wifi -type f | LANG=C sort | xargs sha256sum > SHA256SUM.txt

# Find duplicate entries in wifi
grep -v '  intel_bluetooth/' < SHA256SUM.txt | cut -d ' ' -f 1 | LANG=C sort | uniq -c | grep -v '^ *1 ' |sort -n | \
while IFS= read -r LINE ; do
    printf "%s\n" "$LINE"
    SHA="$(printf %s "$LINE" | awk '{print $2;}')"
    grep --color "^$SHA " < SHA256SUM.txt
done
