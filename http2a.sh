#!/bin/bash

start_time=$(date +%s)

while true; do
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))

    if [ "$elapsed_time" -ge $2 ]; then
        break
    fi

	node known.js $1 10 $3 $4 $5 $6
done
