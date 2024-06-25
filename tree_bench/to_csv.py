#!/bin/python3

# note: before going through this, filter log with:
#     `grep -P 'name": |thrpt:.*Kelem'`

import csv
import sys
import json
import re


FIELD_NAMES = [
    'name',
    'set_size_m',
    'batch_size_k',
    'arity',
    'total_memory_m',
    'num_hashing_per_batch',
    'disk_bytes_per_update',
    'k_updates_per_sec',
]
writer = csv.DictWriter(sys.stdout, fieldnames=FIELD_NAMES)
writer.writeheader()


record = None
for line in sys.stdin:
    if record is None:
        line = re.sub(r"(\w+):", '"\\1":', line)
        line = line.replace("'", '"')
        record = json.loads(line)
    else:
        m = re.search(r"thrpt:\s+\[([\d.]+) Kelem", line)
        if not m:
            raise "Didn't match"
        record['k_updates_per_sec'] = float(m.group(1))
        writer.writerow(record)
        record = None