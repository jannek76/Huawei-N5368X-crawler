#!/bin/sh
SCRIPT_DIR=./
LOG_DIR=/var/log/huawei-n5368x-crawler/
DATE=$(date '+%Y-%m-%d')

cd $SCRIPT_DIR

python3 huawei-n5368x-crawler.py >>$LOG_DIR/huawei-n5368x-crawler-$DATE-info.log 2>>$LOG_DIR/huawei-n5368x-crawler-$DATE-error.log

