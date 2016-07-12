#!/bin/bash

(git describe 2>/dev/null || pwd | sed -e "s/.*\\///" | sed -e "s/[^-]*//") | tail -c +2
