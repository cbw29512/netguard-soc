# Security Policy

NetGuard SOC is security tooling. Treat configuration, telemetry, credentials, network topology, and screenshots as potentially sensitive.

## Reporting a vulnerability

Do not post live credentials, private IP inventories, tokens, certificates, packet captures, or exploit details containing private infrastructure data in public issues. Contact the repository owner privately when possible.

## Deployment expectations

- Run NetGuard only on systems and networks you own or are authorized to monitor.
- Keep secrets outside Git and inject them through approved runtime mechanisms.
- Rotate any credential that may have been exposed.
- Review container image provenance and dependency updates.
- Restrict service bindings and firewall access to the minimum required.
- Do not expose Grafana, InfluxDB, sensor endpoints, or administrative interfaces directly to the public internet without appropriate authentication and network controls.

## Public-release gate

A production-quality release should include secret scanning, dependency/container scanning, automated tests, configuration validation, secure-default review, and a documented rollback/recovery path.
