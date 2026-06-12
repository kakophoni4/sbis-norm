#!/bin/bash
# Скрипт-обертка для вызова certmgr с правильными кавычками
CONTAINER_NAME="$1"
DEST_FILE="$2"
/opt/cprocsp/bin/amd64/certmgr -export -cont "$CONTAINER_NAME" -dest "$DEST_FILE"
