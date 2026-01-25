#!/usr/bin/env python3
"""NetGuard Pipeline Health Monitor"""
import os
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent / "lib"))
from safe_json import atomic_json_write

def check_health():
    health = {
        'timestamp': datetime.now().isoformat(),
        'status': 'healthy',
        'checks': {}
    }
    
    files_to_check = {
        'telemetry': {
            'path': '/var/lib/netguard/router_telemetry.json',
            'max_age_seconds': 600  # 10 minutes
        },
        'findings': {
            'path': '/var/lib/netguard/router_findings.json',
            'max_age_seconds': 600
        },
        'syslog': {
            'path': '/var/lib/netguard/router_syslog_findings.json',
            'max_age_seconds': 120
        },
        'ai_brief': {
            'path': '/var/lib/netguard/router_ai_brief.json',
            'max_age_seconds': 180
        }
    }
    
    now = datetime.now()
    
    for name, config in files_to_check.items():
        check = {'path': config['path']}
        
        try:
            stat = os.stat(config['path'])
            age = (now - datetime.fromtimestamp(stat.st_mtime)).total_seconds()
            check['age_seconds'] = int(age)
            check['last_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            # Validate JSON
            try:
                with open(config['path']) as f:
                    json.load(f)
                check['valid_json'] = True
            except json.JSONDecodeError:
                check['valid_json'] = False
                health['status'] = 'degraded'
            
            # Check freshness
            if age > config['max_age_seconds']:
                check['status'] = 'stale'
                health['status'] = 'degraded'
            else:
                check['status'] = 'ok'
                
        except FileNotFoundError:
            check['status'] = 'missing'
            health['status'] = 'unhealthy'
        except Exception as e:
            check['status'] = 'error'
            check['error'] = str(e)
            health['status'] = 'unhealthy'
        
        health['checks'][name] = check
    
    # Write health status
    atomic_json_write('/var/lib/netguard/health.json', health)
    
    # Print summary
    print(f"Status: {health['status'].upper()}")
    for name, check in health['checks'].items():
        icon = '✓' if check.get('status') == 'ok' else '✗'
        print(f"  {icon} {name}: {check.get('status', 'unknown')}")
    
    return 0 if health['status'] == 'healthy' else 1

if __name__ == '__main__':
    sys.exit(check_health())
