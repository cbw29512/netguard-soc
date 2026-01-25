#!/usr/bin/env python3
"""SSH Connection Pool - Reuse SSH connections to reduce overhead"""
import subprocess
import time
from threading import Lock
from pathlib import Path

class RouterSSHPool:
    """Maintains persistent SSH ControlMaster connection"""
    def __init__(self, host, user, port, key_path, known_hosts_path, max_age=300):
        self.host = host
        self.user = user
        self.port = str(port)
        self.key_path = str(key_path)
        self.known_hosts_path = str(known_hosts_path)
        self.max_age = max_age
        self._control_path = f"/tmp/netguard_ssh_{host}_{user}"
        self._last_used = 0
        self._lock = Lock()
        self._master_started = False
    
    def _ensure_master(self):
        """Ensure ControlMaster is running"""
        with self._lock:
            now = time.time()
            
            # Check if we need to restart
            if self._master_started and (now - self._last_used) < self.max_age:
                # Still valid
                self._last_used = now
                return
            
            # Kill old master if exists
            subprocess.run(
                ["ssh", "-O", "exit", "-S", self._control_path, f"{self.user}@{self.host}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Start new ControlMaster
            cmd = [
                "ssh",
                "-M",  # ControlMaster mode
                "-N",  # No remote command
                "-f",  # Background
                "-p", self.port,
                "-i", self.key_path,
                "-o", f"UserKnownHostsFile={self.known_hosts_path}",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "BatchMode=yes",
                "-o", "ControlPath=" + self._control_path,
                "-o", "ControlPersist=5m",
                "-o", "ConnectTimeout=6",
                f"{self.user}@{self.host}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to start SSH ControlMaster: {result.stderr}")
            
            self._master_started = True
            self._last_used = now
    
    def run_command(self, remote_script):
        """Execute command using pooled connection"""
        self._ensure_master()
        
        cmd = [
            "ssh",
            "-p", self.port,
            "-i", self.key_path,
            "-o", f"UserKnownHostsFile={self.known_hosts_path}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes",
            "-o", "ControlPath=" + self._control_path,
            "-o", "ConnectTimeout=6",
            f"{self.user}@{self.host}",
            "sh", "-s"
        ]
        
        result = subprocess.run(cmd, input=remote_script.encode(), capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode(errors="replace").strip() or f"ssh rc={result.returncode}")
        
        return result.stdout.decode("utf-8", errors="replace")
    
    def close(self):
        """Explicitly close the connection pool"""
        subprocess.run(
            ["ssh", "-O", "exit", "-S", self._control_path, f"{self.user}@{self.host}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self._master_started = False

# Global pool instance
_pool = None

def get_router_ssh_pool(host="192.168.50.1", user="nucboxr", port="22", 
                         key_path="/var/lib/netguard/keys/netguard_router_ed25519",
                         known_hosts="/var/lib/netguard/ssh_known_hosts"):
    """Get or create global SSH pool"""
    global _pool
    if _pool is None:
        _pool = RouterSSHPool(host, user, port, key_path, known_hosts)
    return _pool
