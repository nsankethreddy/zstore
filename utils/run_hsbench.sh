#!/usr/bin/env bash
set -xeuo pipefail

# go install github.com/markhpc/hsbench@latest


# hsbench -a 3JZ0SVK94Z55OZU5J1N0 -s OdzEPyDDZ0ls1haDUu1NVWkJDcnG74Lb7XylfXRM -u http://12.12.12.1:2000 -z 4K -d 10 -t 10 -b 10
hsbench -a test -s test -u http://12.12.12.1:2000 -z 4K -d 10 -t 60 -b 1
