#!/usr/bin/env bash

# Loop over each size and call ./run_prot1.sh <size> three times
for size in 128 256 512 768 1024; do
  echo "=== Running ./run_prot1.sh $size (×3) ==="
  for i in {1..3}; do
    ./run_prot1.sh "$size"
  done
  echo
done
