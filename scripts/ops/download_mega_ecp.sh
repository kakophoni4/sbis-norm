#!/bin/bash


MEGA_LINK="https://mega.nz/folder/k1UE0IxQ#YZIpbOp2Wcxt4HnPKHLViw"
LOCAL_DIR="/tmp/mega_downloads"
INN_LIST=("9715376022" "7715600802")

mkdir -p "$LOCAL_DIR"

echo "MEGA..."
mega-get "$MEGA_LINK" "$LOCAL_DIR"


for INN in "${INN_LIST[@]}"; do
    if [ -d "$LOCAL_DIR/$INN" ] || [ -f "$LOCAL_DIR/$INN.zip" ]; then
        echo "$INN $LOCAL_DIR/$INN"
    else
        echo "..."
        mega-get "$MEGA_LINK/$INN" "$LOCAL_DIR/$INN"
    fi
done
