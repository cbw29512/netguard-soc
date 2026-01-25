#!/usr/bin/env python3
"""
NetGuard AI Security Brain v2.0
RAG-enabled network security AI with pattern learning
"""
import json
import time
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque, defaultdict
import re

sys.path.insert(0, '/opt/netguard/sensors/lib')
from safe_json import read_json_safe, atomic_json_write

# Paths
TELEMETRY = Path("/var/lib/netguard/router_telemetry.json")
FINDINGS = Path("/var/lib/netguard/router_findings.json")
INVENTORY = Path("/var/lib/netguard/router_inventory.json")
HEALTH = Path("/var/lib/netguard/health.json")
WIFI_ASSOC = Path("/var/lib/netguard/router_wifi_assoc.json")
SYSLOG_DB = Path("/var/lib/netguard/router_syslog.sqlite")
AI_STATE = Path("/var/lib/netguard/ai_guard_state.json")
AI_KNOWLEDGE = Path("/var/lib/netguard/rag/ai_knowledge.json")
THOUGHTS_LOG = Path("/var/lib/netguard/ai_thoughts.log")

OLLAMA_MODEL = "llama3.2:latest"

# Security Knowledge Base - teaches the AI about network security
SECURITY_KNOWLEDGE = """
You are NetGuard AI, a network security and optimization specialist for a home/small office network.

YOUR ROLE:
- Monitor network devices for suspicious activity
- Detect anomalies in traffic patterns
- Identify unauthorized devices
- Recommend security hardening measures
- Optimize WiFi band distribution
- Track device behavior over time

SECURITY CONCERNS TO WATCH:
1. Unknown devices with randomized MACs (iOS/Android privacy feature) - suggest whitelisting or identifying
2. IP drift - devices getting different IPs than reserved - indicates DHCP issues or MAC spoofing
3. Unusual connection times - devices connecting at odd hours
4. High bandwidth consumers - potential exfiltration or compromised devices
5. Devices on wrong WiFi band - 2.4GHz congestion when 5GHz/6GHz available
6. Failed SSH attempts - brute force attacks
7. DNS anomalies - potential malware C2 communication
8. ARP inconsistencies - potential spoofing attacks

OPTIMIZATION SUGGESTIONS:
- Move capable devices to 5GHz/6GHz for better performance
- Set static IPs for critical infrastructure
- Segment IoT devices from main network
- Enable WPA3 where supported
- Regular firmware updates for router

RESPONSE STYLE:
- Be concise and actionable
- Prioritize security over convenience
- Explain risks in simple terms
- Suggest specific next steps
"""

class AISecurityBrain:
    def __init__(self):
        self.thoughts = deque(maxlen=100)
        self.device_history = defaultdict(list)
        self.pattern_memory = {}
        self.last_analysis = {}
        self.ollama_available = self._check_ollama()
        
        # Load previous state
        self._load_state()
        
        # Initialize knowledge
        self._init_knowledge()
        
        status = "Ollama AI enabled" if self.ollama_available else "Pattern mode (no Ollama)"
        self.log_thought(f"🧠 AI Security Brain v2.0 activated - {status}", "info")
    
    def _check_ollama(self):
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _init_knowledge(self):
        """Initialize or load knowledge base"""
        if AI_KNOWLEDGE.exists():
            self.knowledge = read_json_safe(AI_KNOWLEDGE, {})
        else:
            self.knowledge = {
                'learned_patterns': {},
                'device_profiles': {},
                'baseline_hours': {},
                'threat_history': []
            }
            self._save_knowledge()
    
    def _load_state(self):
        """Load previous AI state"""
        state = read_json_safe(AI_STATE, {})
        self.device_memory = state.get('device_memory', {})
        for t in state.get('thoughts', []):
            self.thoughts.append(t)
    
    def _save_state(self):
        """Save AI state"""
        state = {
            'last_update': datetime.now().isoformat(),
            'thoughts': list(self.thoughts),
            'device_memory': self.device_memory,
            'ollama_available': self.ollama_available
        }
        atomic_json_write(AI_STATE, state)
    
    def _save_knowledge(self):
        """Save learned knowledge"""
        AI_KNOWLEDGE.parent.mkdir(parents=True, exist_ok=True)
        atomic_json_write(AI_KNOWLEDGE, self.knowledge)
    
    def query_syslog(self, query, limit=50):
        """Search syslog for patterns"""
        try:
            conn = sqlite3.connect(SYSLOG_DB)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ts, prog, msg FROM events 
                WHERE msg LIKE ? OR prog LIKE ?
                ORDER BY id DESC LIMIT ?
            """, (f'%{query}%', f'%{query}%', limit))
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            return []
    
    def get_hourly_patterns(self):
        """Analyze device activity by hour"""
        try:
            conn = sqlite3.connect(SYSLOG_DB)
            cursor = conn.cursor()
            # Get DHCP activity by hour
            cursor.execute("""
                SELECT strftime('%H', ts) as hour, COUNT(*) as cnt
                FROM events WHERE prog = 'dnsmasq-dhcp'
                GROUP BY hour ORDER BY hour
            """)
            hourly = {row[0]: row[1] for row in cursor.fetchall()}
            conn.close()
            return hourly
        except:
            return {}
    
    def analyze_with_context(self, situation, context_data):
        """Use Ollama with full context for analysis"""
        if not self.ollama_available:
            return None
        
        prompt = f"""{SECURITY_KNOWLEDGE}

CURRENT NETWORK STATE:
{json.dumps(context_data, indent=2)}

SITUATION:
{situation}

Provide a brief security assessment and recommendation (max 2 sentences):"""

        try:
            result = subprocess.run(
                ["ollama", "run", OLLAMA_MODEL, prompt],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                response = result.stdout.strip()
                # Truncate long responses
                if len(response) > 200:
                    response = response[:200] + "..."
                return response
        except:
            pass
        return None
    
    def learn_device_pattern(self, mac, device_info):
        """Learn normal behavior for a device"""
        hour = datetime.now().hour
        
        if mac not in self.knowledge['device_profiles']:
            self.knowledge['device_profiles'][mac] = {
                'hostname': device_info.get('hostname', 'Unknown'),
                'typical_hours': [],
                'typical_band': None,
                'first_seen': datetime.now().isoformat(),
                'connection_count': 0
            }
        
        profile = self.knowledge['device_profiles'][mac]
        profile['connection_count'] += 1
        if hour not in profile['typical_hours']:
            profile['typical_hours'].append(hour)
            profile['typical_hours'] = profile['typical_hours'][-24:]  # Keep last 24 unique hours
        
        # Learn WiFi band preference
        band = device_info.get('wifi_band')
        if band:
            profile['typical_band'] = band
        
        self._save_knowledge()
    
    def detect_anomalies(self, devices, findings):
        """Detect anomalies based on learned patterns"""
        anomalies = []
        hour = datetime.now().hour
        
        for device in devices:
            mac = device.get('mac', '').lower()
            profile = self.knowledge['device_profiles'].get(mac, {})
            
            # Check for unusual connection time
            if profile.get('typical_hours') and len(profile['typical_hours']) > 5:
                if hour not in profile['typical_hours']:
                    anomalies.append({
                        'type': 'unusual_time',
                        'device': device.get('hostname', mac),
                        'message': f"Device active at unusual hour ({hour}:00)"
                    })
        
        return anomalies
    
    def observe_network(self):
        """Main observation loop"""
        telemetry = read_json_safe(TELEMETRY, {})
        findings = read_json_safe(FINDINGS, {})
        inventory = read_json_safe(INVENTORY, {})
        wifi_assoc = read_json_safe(WIFI_ASSOC, {})
        health = read_json_safe(HEALTH, {})
        
        if not telemetry.get('ok'):
            return
        
        # Get current devices
        clients = telemetry.get('clients', {}) or {}
        leases = clients.get('dhcp_leases', []) or []
        arp = clients.get('arp', []) or []
        
        # Build context
        context = {
            'device_count': len(leases),
            'online_count': len(arp),
            'alerts': findings.get('alerts', []),
            'health': health.get('status', 'unknown'),
            'wifi_bands': {}
        }
        
        # Get WiFi band info
        wifi_bases = wifi_assoc.get('wifi', {}).get('bases', {})
        for band, info in wifi_bases.items():
            context['wifi_bands'][band] = {
                'count': info.get('assoc_count', 0),
                'macs': info.get('assoc_macs', [])
            }
        
        # Build MAC to band mapping
        mac_to_band = {}
        for band, info in wifi_bases.items():
            band_label = {'wl0': '2.4GHz', 'wl1': '5GHz', 'wl2': '6GHz'}.get(band, band)
            for mac in info.get('assoc_macs', []):
                mac_to_band[mac.lower()] = band_label
        
        # Process each device
        current_macs = set()
        reservations = {r['mac'].lower(): r for r in inventory.get('reservations', [])}
        
        for lease in leases:
            mac = lease.get('mac', '').lower()
            if not mac:
                continue
            
            current_macs.add(mac)
            ip = lease.get('ip', '')
            hostname = lease.get('hostname', 'Unknown')
            is_known = mac in reservations
            wifi_band = mac_to_band.get(mac)
            
            device_info = {
                'hostname': hostname,
                'ip': ip,
                'known': is_known,
                'wifi_band': wifi_band
            }
            
            # Learn pattern
            self.learn_device_pattern(mac, device_info)
            
            # Track new devices
            if mac not in self.device_memory:
                self.device_memory[mac] = {
                    'hostname': hostname,
                    'ip': ip,
                    'first_seen': datetime.now().isoformat()
                }
                
                if is_known:
                    name = reservations[mac].get('name', hostname)
                    self.log_thought(f"✓ {name} connected ({ip})", "info")
                else:
                    self.log_thought(f"❓ UNKNOWN: {hostname} at {ip} [{mac[:8]}...]", "warning")
                    
                    # Get AI assessment for unknown device
                    if self.ollama_available:
                        assessment = self.analyze_with_context(
                            f"Unknown device '{hostname}' joined network at {ip} with MAC {mac}",
                            context
                        )
                        if assessment:
                            self.log_thought(f"🤖 {assessment}", "suggestion")
        
        # Check for devices that left
        previous_macs = set(self.device_memory.keys())
        for mac in previous_macs - current_macs:
            device = self.device_memory.pop(mac, {})
            self.log_thought(f"👋 {device.get('hostname', 'Device')} disconnected", "info")
        
        # Analyze alerts
        alerts = findings.get('alerts', [])
        for alert in alerts:
            kind = alert.get('kind', '')
            severity = alert.get('severity', 'low')
            
            # Rate limit alerts
            alert_key = f"{kind}_{severity}"
            last_time = self.last_analysis.get(alert_key, 0)
            if time.time() - last_time < 1800:  # 30 min cooldown
                continue
            self.last_analysis[alert_key] = time.time()
            
            if severity in ('medium', 'high'):
                self.log_thought(f"🚨 {kind.upper()}: {alert.get('examples', [''])[0][:50]}", "alert")
                
                if self.ollama_available:
                    assessment = self.analyze_with_context(
                        f"Security alert: {kind} (severity: {severity}). Examples: {alert.get('examples', [])}",
                        context
                    )
                    if assessment:
                        self.log_thought(f"🤖 {assessment}", "suggestion")
        
        # Periodic deep analysis (every 10 cycles)
        if len(self.thoughts) % 10 == 0:
            self._periodic_analysis(context)
        
        self._save_state()
    
    def _periodic_analysis(self, context):
        """Periodic deeper analysis"""
        # Check WiFi optimization
        wifi = context.get('wifi_bands', {})
        wl0_count = wifi.get('wl0', {}).get('count', 0)
        wl1_count = wifi.get('wl1', {}).get('count', 0)
        wl2_count = wifi.get('wl2', {}).get('count', 0)
        
        if wl0_count > (wl1_count + wl2_count + 2):
            self.log_thought(
                f"⚡ WiFi: {wl0_count} on 2.4GHz, {wl1_count} on 5GHz - consider band steering",
                "suggestion"
            )
        
        # Query recent interesting syslog events
        dhcp_events = self.query_syslog('DHCPACK', 10)
        if dhcp_events:
            unique_hosts = set(e[2].split()[-1] if e[2] else '' for e in dhcp_events)
            self.log_thought(f"📊 Recent DHCP: {len(unique_hosts)} unique hosts", "info")
    
    def log_thought(self, thought, level="info"):
        """Log an AI thought"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'thought': thought,
            'level': level
        }
        self.thoughts.append(entry)
        
        try:
            with open(THOUGHTS_LOG, 'a') as f:
                f.write(f"[{entry['timestamp']}] [{level.upper()}] {thought}\n")
        except:
            pass
        
        print(f"[AI] {thought}")
    
    def run_forever(self):
        """Main loop"""
        while True:
            try:
                self.observe_network()
                time.sleep(30)
            except KeyboardInterrupt:
                self.log_thought("🧠 AI Security Brain shutting down", "info")
                self._save_state()
                break
            except Exception as e:
                self.log_thought(f"⚠️ Error: {str(e)[:50]}", "error")
                time.sleep(10)

if __name__ == '__main__':
    brain = AISecurityBrain()
    brain.run_forever()
