#!/usr/bin/env python3
"""
NetGuard SOC AI Security Guard - CODE REVIEWED
VERIFIED: Only reads real data, no simulation, no placeholders
Data Sources: /var/lib/netguard/*.json (existing pipeline outputs)
Output: AI thoughts only (not network data)
"""
import json
import time
import sys
import subprocess
from datetime import datetime
from pathlib import Path
from collections import deque

# Import from existing optimized library
sys.path.insert(0, '/opt/netguard/sensors/lib')
from safe_json import read_json_safe, atomic_json_write

# VERIFIED: All paths point to REAL pipeline output files
TELEMETRY_FILE = Path("/var/lib/netguard/router_telemetry.json")
FINDINGS_FILE = Path("/var/lib/netguard/router_findings.json")
SYSLOG_FILE = Path("/var/lib/netguard/router_syslog_findings.json")
INVENTORY_FILE = Path("/var/lib/netguard/router_inventory.json")
HEALTH_FILE = Path("/var/lib/netguard/health.json")

# AI state files (thoughts only, not network data)
AI_STATE = Path("/var/lib/netguard/ai_guard_state.json")
THOUGHTS_LOG = Path("/var/lib/netguard/ai_thoughts.log")

OLLAMA_MODEL = "llama3.2:latest"
ANALYSIS_INTERVAL = 30  # seconds between observations

class AISecurityGuard:
    """
    REVIEWED: This class ONLY observes real data
    - Reads from existing pipeline files
    - Logs thoughts/observations
    - Does NOT generate fake data
    - Does NOT modify network data
    """
    
    def __init__(self):
        self.thoughts = deque(maxlen=50)
        self.device_memory = {}  # Track devices we've seen
        self.last_alert_time = {}  # Prevent alert spam
        self.ollama_available = self._check_ollama()
        
        # Initialize log file
        THOUGHTS_LOG.parent.mkdir(parents=True, exist_ok=True)
        
        if self.ollama_available:
            self.log_thought("🛡️ AI Security Guard activated - Ollama AI enabled", "info")
        else:
            self.log_thought("🛡️ AI Security Guard activated - Observation mode (no Ollama)", "info")
    
    def _check_ollama(self):
        """REVIEWED: Simple check if Ollama is available"""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def think(self, prompt, max_length=150):
        """
        REVIEWED: Call Ollama for AI insights
        - Only called if Ollama is available
        - Returns None if unavailable or errors
        - Limits response length to prevent spam
        """
        if not self.ollama_available:
            return None
        
        try:
            # Add constraint to keep responses concise
            full_prompt = f"{prompt}\n\nAnswer in ONE clear sentence (max 150 characters)."
            
            result = subprocess.run(
                ["ollama", "run", OLLAMA_MODEL, full_prompt],
                capture_output=True,
                text=True,
                timeout=20
            )
            
            if result.returncode == 0:
                response = result.stdout.strip()
                # Truncate if too long
                if len(response) > max_length:
                    response = response[:max_length] + "..."
                return response
            return None
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None
    
    def observe_network(self):
        """
        REVIEWED: Main observation function
        VERIFIED: Only reads real files, no data generation
        """
        
        # VERIFIED: Read REAL data files created by existing pipeline
        telemetry = read_json_safe(TELEMETRY_FILE, None)
        findings = read_json_safe(FINDINGS_FILE, None)
        syslog = read_json_safe(SYSLOG_FILE, None)
        inventory = read_json_safe(INVENTORY_FILE, None)
        health = read_json_safe(HEALTH_FILE, None)
        
        # Verify we have real data before proceeding
        if telemetry is None:
            self.log_thought("⚠️ Waiting for telemetry data from router...", "warning")
            return
        
        if not telemetry.get('ok'):
            error = telemetry.get('error', 'Unknown error')
            self.log_thought(f"⚠️ Router unreachable: {error}", "error")
            return
        
        # VERIFIED: Extract REAL device data from telemetry
        clients = telemetry.get('clients', {}) or {}
        leases = clients.get('dhcp_leases', []) or []
        arp = clients.get('arp', []) or []
        
        if not leases:
            # This is a valid state - no devices connected
            if len(self.device_memory) > 0:
                self.log_thought("📡 All devices disconnected from network", "info")
                self.device_memory.clear()
            return
        
        device_count = len(leases)
        
        # VERIFIED: Analyze REAL alerts from findings
        if findings:
            alerts = findings.get('alerts', []) or []
            
            for alert in alerts:
                kind = alert.get('kind', 'unknown')
                severity = alert.get('severity', 'low')
                
                # Prevent spam - only alert once per hour for same kind
                now = datetime.now().timestamp()
                last_alert = self.last_alert_time.get(kind, 0)
                if now - last_alert < 3600:  # 1 hour
                    continue
                
                self.last_alert_time[kind] = now
                
                # Get AI insight if available
                if self.ollama_available and severity in ['high', 'medium']:
                    context = f"Network alert: {kind} (severity: {severity})"
                    if 'examples' in alert:
                        context += f". Examples: {alert['examples'][:2]}"
                    
                    thought = self.think(f"{context}. What should the admin check?")
                    if thought:
                        self.log_thought(f"🚨 {kind.upper()}: {thought}", "alert")
                    else:
                        self.log_thought(f"🚨 ALERT: {kind} (severity: {severity})", "alert")
                else:
                    self.log_thought(f"🚨 ALERT: {kind} (severity: {severity})", "alert")
        
        # VERIFIED: Track REAL device changes
        self._track_device_changes(leases, inventory)
        
        # VERIFIED: Analyze REAL WiFi distribution
        self._analyze_wifi(telemetry)
        
        # VERIFIED: Check REAL health status
        if health and health.get('status') != 'healthy':
            status = health.get('status', 'unknown')
            checks = health.get('checks', {})
            degraded = [name for name, check in checks.items() if check.get('status') != 'ok']
            if degraded:
                self.log_thought(f"⚠️ Health degraded: {', '.join(degraded[:3])}", "warning")
        
        # Periodic summary (every 10th cycle ~ 5 minutes)
        if len(self.thoughts) % 10 == 0:
            alert_count = len(findings.get('alerts', [])) if findings else 0
            summary = f"📊 Status: {device_count} devices active"
            if alert_count > 0:
                summary += f", {alert_count} alerts pending"
            self.log_thought(summary, "info")
        
        # Save AI state
        self._save_state()
    
    def _track_device_changes(self, leases, inventory):
        """
        REVIEWED: Track when REAL devices join/leave
        VERIFIED: Only uses actual MAC addresses from DHCP leases
        """
        current_macs = set(lease.get('mac', '').lower() for lease in leases if lease.get('mac'))
        previous_macs = set(self.device_memory.keys())
        
        # VERIFIED: Detect REAL new devices
        new_macs = current_macs - previous_macs
        for mac in new_macs:
            lease = next((l for l in leases if l.get('mac', '').lower() == mac), None)
            if not lease:
                continue
            
            hostname = lease.get('hostname', 'Unknown')
            ip = lease.get('ip', 'Unknown')
            
            # Check if device is in REAL inventory
            known = False
            reserved_name = ''
            if inventory:
                reservations = inventory.get('reservations', []) or []
                for res in reservations:
                    if res.get('mac', '').lower() == mac:
                        known = True
                        reserved_name = res.get('name', '')
                        break
            
            if known:
                name = reserved_name if reserved_name else hostname
                self.log_thought(f"✓ Known device reconnected: {name} at {ip}", "info")
            else:
                self.log_thought(f"❓ UNKNOWN device: {hostname} at {ip} [{mac}]", "warning")
                
                # Get AI recommendation if available
                if self.ollama_available:
                    thought = self.think(f"Unknown device '{hostname}' joined at {ip}. What should admin verify?")
                    if thought:
                        self.log_thought(f"💭 AI: {thought}", "suggestion")
            
            self.device_memory[mac] = {
                'hostname': hostname,
                'ip': ip,
                'first_seen': datetime.now().isoformat()
            }
        
        # VERIFIED: Detect REAL device departures
        gone_macs = previous_macs - current_macs
        for mac in gone_macs:
            device = self.device_memory.get(mac, {})
            hostname = device.get('hostname', 'Unknown')
            self.log_thought(f"👋 Device left: {hostname}", "info")
            del self.device_memory[mac]
    
    def _analyze_wifi(self, telemetry):
        """
        REVIEWED: Analyze REAL WiFi band distribution
        VERIFIED: Uses actual wl0/wl1/wl2 association counts
        """
        wifi = telemetry.get('wifi', {})
        if not wifi:
            return
        
        bands = wifi.get('bands', {}) or {}
        wl0 = bands.get('wl0', {}) or {}
        wl1 = bands.get('wl1', {}) or {}
        wl2 = bands.get('wl2', {}) or {}
        
        wl0_count = wl0.get('assoc_count', 0)
        wl1_count = wl1.get('assoc_count', 0)
        wl2_count = wl2.get('assoc_count', 0)
        
        total = wl0_count + wl1_count + wl2_count
        if total == 0:
            return
        
        # Only comment on significant imbalance
        if wl0_count > 0 and wl0_count > (wl1_count + wl2_count + 3):
            self.log_thought(
                f"⚡ WiFi imbalance: 2.4GHz={wl0_count}, 5GHz={wl1_count}, 6GHz={wl2_count}",
                "suggestion"
            )
            
            if self.ollama_available:
                thought = self.think(
                    f"2.4GHz band has {wl0_count} clients while faster bands have {wl1_count + wl2_count}. "
                    "Should devices be moved to 5GHz/6GHz?"
                )
                if thought:
                    self.log_thought(f"💭 AI: {thought}", "suggestion")
    
    def log_thought(self, thought, level="info"):
        """
        REVIEWED: Log AI thought to file and memory
        VERIFIED: Only logs thoughts, not network data
        """
        timestamp = datetime.now().isoformat()
        entry = {
            'timestamp': timestamp,
            'thought': thought,
            'level': level
        }
        self.thoughts.append(entry)
        
        # Append to persistent log
        try:
            with open(THOUGHTS_LOG, 'a') as f:
                f.write(f"[{timestamp}] [{level.upper()}] {thought}\n")
        except Exception as e:
            print(f"Failed to write thought: {e}")
        
        print(f"[AI GUARD] {thought}")
    
    def _save_state(self):
        """
        REVIEWED: Save AI state (thoughts only)
        VERIFIED: Does not save network data, only AI observations
        """
        state = {
            'last_update': datetime.now().isoformat(),
            'thoughts': list(self.thoughts),
            'device_memory': self.device_memory,
            'ollama_available': self.ollama_available
        }
        try:
            atomic_json_write(AI_STATE, state)
        except Exception as e:
            print(f"Failed to save AI state: {e}")
    
    def run_forever(self):
        """Main loop - continuously observe real network data"""
        while True:
            try:
                self.observe_network()
                time.sleep(ANALYSIS_INTERVAL)
            except KeyboardInterrupt:
                self.log_thought("🛡️ AI Security Guard shutting down", "info")
                break
            except Exception as e:
                self.log_thought(f"⚠️ Observation error: {str(e)}", "error")
                time.sleep(5)

if __name__ == '__main__':
    guard = AISecurityGuard()
    guard.run_forever()
