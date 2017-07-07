#!/bin/bash
TIMESTAMP=`git log -1 --format=%ct`
DATE=`date +"%m/%d/%y" -ud @$TIMESTAMP`
COMMIT_NUMBER=`git rev-list --count HEAD`
echo "$DATE (r$COMMIT_NUMBER)"
