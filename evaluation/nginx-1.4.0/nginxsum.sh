#!/usr/bin/env bash

2>&1
1>/dev/null
COUNT=${1:-1}

for i in $(seq 1 $COUNT)
do
    curl localhost >/dev/null 2>&1
done
