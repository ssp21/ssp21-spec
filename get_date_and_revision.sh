#!/bin/bash
DATE=$(git log -1 --format=%cd --date=format:%m/%d/%y)
COMMIT_NUMBER=$(git rev-list --count HEAD)
echo "$DATE (r$COMMIT_NUMBER)"
