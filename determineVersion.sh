#!/bin/bash
if [ $(git rev-parse --show-toplevel 2>/dev/null) == $(pwd) ]; then
  git describe --tags 2>/dev/null | tail -c +2
else
  pwd | sed -e "s/.*\\///" | sed -e "s/[^-]*//" | tail -c +2
fi
