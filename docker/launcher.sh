#!/bin/bash

_term() { 
  echo "Caught SIGTERM signal!" 
  kill -TERM "$child"
}

trap _term SIGTERM

env

./modes/$mode/env_replace.sh
./usr/local/bin/click /modes/$mode/$mode.click &
sleep 5

./modes/$mode/post_config.sh

child=$!

wait "$child"
