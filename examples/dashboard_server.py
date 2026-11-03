#!/usr/bin/env python3
"""
Launch the local horkos-oss dashboard over a runs directory.

Each run that called save_run(result, out_dir, target_score) (or used
output_dir in RunOptions and then save_run) appears in the index.

    python examples/dashboard_server.py runs          # serve ./runs on 127.0.0.1:8787
    python examples/dashboard_server.py runs 8080      # custom port
"""
import sys
from horkos_sec import serve

root = sys.argv[1] if len(sys.argv) > 1 else "runs"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8787
serve(root, host="127.0.0.1", port=port)
