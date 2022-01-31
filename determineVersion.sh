#!/bin/bash

(git describe --tags 2>/dev/null || pwd | sed -e "s/.*\\///" | sed -e "s/[^-]*//") | tail -c +2
