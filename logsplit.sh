#!/bin/sh

LOG_DIR="/home/fastj"
D=`date -d '1 day ago' +%Y%m%d`
sh stop.sh
mv $LOG_DIR/fastj.log $LOG_DIR/fastj.log-$D
sh start.sh
gzip -f $LOG_DIR/fastj.log-$D
rm -f  $LOG_DIR/fastj.log-`date -d '30 day ago' +%Y%m%d`.gz

