# NetGuard Build Manifest

This repo is the reproducible config source for NetGuard on Ubuntu.

## Enterprise stack
- InfluxDB 2.x + Grafana via Docker Compose
- Compose path: /opt/netguard/enterprise/docker-compose.yml
- Data path: /var/lib/netguard/enterprise/
- systemd unit: /etc/systemd/system/netguard-enterprise.service

## Static IP reservations
- /opt/netguard/config/static_ip_reservations.csv

## Notes
- Secrets live in /opt/netguard/enterprise/secrets/ (NOT committed to git)
- Snapshots live in /var/lib/netguard/snapshots/
