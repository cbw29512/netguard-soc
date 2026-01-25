#!/usr/bin/env python3
"""Safe JSON operations with atomic writes"""
import json
import tempfile
import os
from pathlib import Path

def atomic_json_write(filepath, data, indent=2):
    """Write JSON atomically to prevent corruption"""
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temp file in same directory
    with tempfile.NamedTemporaryFile(
        mode='w',
        dir=filepath.parent,
        delete=False,
        prefix='.tmp_',
        suffix='.json'
    ) as tmp:
        json.dump(data, tmp, indent=indent)
        tmp.flush()
        os.fsync(tmp.fileno())  # Force to disk
        tmp_path = tmp.name
    
    # Atomic rename
    os.replace(tmp_path, filepath)

def read_json_safe(filepath, default=None):
    """Read JSON with error handling"""
    try:
        with open(filepath) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default
