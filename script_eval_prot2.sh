#!/usr/bin/env bash
#
#
# 1) Ensure a size argument is provided
# 2) Run setup with `--size <size>`
# 3) Record start-time, then launch client, smart_contract, server in the background,
#    redirecting each of their stdout into its own temp file
# 4) Wait for all three to exit
# 5) Compute elapsed time
# 6) Read the last two non-empty lines from client2_out.txt and sc2_out.txt,
#    and the last non-empty line from server2_out.txt, assigning each to its own variable
# 7) Append elapsed time + those variables into prot2_output.txt

set -euo pipefail

cargo build --release

# 1) Check for exactly one argument (size)
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <size>"
    exit 1
fi
SIZE="$1"

# 2) Run setup with --size <size> (exit immediately if it fails)
./target/release/setup --size "$SIZE"

# 3) Record start time (seconds since the epoch) and launch each program in the background
START_TIME=$(date +%s)

./target/release/client2         > client2_out.txt       2>&1 &
PID_CLIENT=$!

./target/release/smart_contract2 > sc2_out.txt           2>&1 &
PID_SC=$!

./target/release/server2        > server2_out.txt       2>&1 &
PID_SERVER=$!

# 4) Wait for all three to finish
wait "$PID_CLIENT"
wait "$PID_SC"
wait "$PID_SERVER"

# 5) Record end time and compute elapsed seconds
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))

# 6) POSIX‐compatible extraction of last two non-empty lines from client2_out.txt
CLIENT_RET_BEFORE_LAST_LINE=""
CLIENT_RET_LAST_LINE=""

# Filter out blank lines, take last two into a temp file
grep -v '^$' client2_out.txt | tail -n 2 > _tmp_client_lines.txt
CLIENT_LINE_COUNT=$(wc -l < _tmp_client_lines.txt)

if [ "$CLIENT_LINE_COUNT" -ge 2 ]; then
    CLIENT_RET_BEFORE_LAST_LINE=$(sed -n '1p' _tmp_client_lines.txt)
    CLIENT_RET_LAST_LINE=$(sed -n '2p' _tmp_client_lines.txt)
elif [ "$CLIENT_LINE_COUNT" -eq 1 ]; then
    CLIENT_RET_BEFORE_LAST_LINE="<no second-to-last output>"
    CLIENT_RET_LAST_LINE=$(sed -n '1p' _tmp_client_lines.txt)
else
    CLIENT_RET_BEFORE_LAST_LINE="<no output>"
    CLIENT_RET_LAST_LINE="<no output>"
fi
rm -f _tmp_client_lines.txt

# 6b) POSIX‐compatible extraction of last two non-empty lines from sc_out.txt
SC_RET_BEFORE_LAST_LINE=""
SC_RET_LAST_LINE=""

grep -v '^$' sc2_out.txt | tail -n 2 > _tmp_sc_lines.txt
SC_LINE_COUNT=$(wc -l < _tmp_sc_lines.txt)

if [ "$SC_LINE_COUNT" -ge 2 ]; then
    SC_RET_BEFORE_LAST_LINE=$(sed -n '1p' _tmp_sc_lines.txt)
    SC_RET_LAST_LINE=$(sed -n '2p' _tmp_sc_lines.txt)
elif [ "$SC_LINE_COUNT" -eq 1 ]; then
    SC_RET_BEFORE_LAST_LINE="<no second-to-last output>"
    SC_RET_LAST_LINE=$(sed -n '1p' _tmp_sc_lines.txt)
else
    SC_RET_BEFORE_LAST_LINE="<no output>"
    SC_RET_LAST_LINE="<no output>"
fi
rm -f _tmp_sc_lines.txt

# 6c) POSIX‐compatible extraction of last non-empty line from server2_out.txt
SERVER_RET_LAST_LINE=$(grep -v '^$' server2_out.txt | tail -n 1 || echo "")
if [ -z "$SERVER_RET_LAST_LINE" ]; then
    SERVER_RET_LAST_LINE="<no output>"
fi

# 7) Append everything to prot2_output.txt
{
  echo "=== Run with size=${SIZE} ==="
  echo "COMPUTATION COST:"
  echo "Elapsed time (for the whole exchange): ${ELAPSED} seconds"
  echo "${CLIENT_RET_BEFORE_LAST_LINE}"
  echo "${SC_RET_BEFORE_LAST_LINE}"
  echo "${SERVER_RET_LAST_LINE}"
  echo
  echo "COMMUNICATION COST:"
  echo "${CLIENT_RET_LAST_LINE}"
  echo "${SC_RET_LAST_LINE}"

  echo
  echo
} >> prot2_output.txt
