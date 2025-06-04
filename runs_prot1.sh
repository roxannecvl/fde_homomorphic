#!/usr/bin/env bash

# Loop over each size and call ./script_eval.sh <size> three times
for size in 128 256 512 768 1024; do
  echo "=== Running ./script_eval.sh $size (×3) ==="
  for i in {1..3}; do
    ./script_eval.sh "$size"
  done
  echo
done
