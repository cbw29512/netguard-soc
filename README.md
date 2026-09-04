# NetGuard SOC

NetGuard SOC is a home-lab / small-environment security operations project for collecting telemetry, operating sensors, visualizing security data, and experimenting with SOC workflows on Ubuntu.

The repository is intended to be the reproducible configuration and code source for the lab. It is **not** a turnkey managed-security product and should not be deployed to an untrusted network without reviewing every service, credential, port, and default first.

## Repository areas

- `app/` — application code
- `config/` — lab configuration
- `sensors/` — sensor components
- `soc/` — SOC functionality
- `soc_ai/` — AI-assisted SOC experiments
- `enterprise/` — Docker-based InfluxDB/Grafana stack and related enterprise-style lab components
- `static/` — static assets
- `MANIFEST.md` — reproducible-host build notes

## Security model

Secrets must stay outside Git. The current build manifest expects secrets under `/opt/netguard/enterprise/secrets/`, and `.gitignore` blocks common secret, environment, cache, and virtual-environment paths.

Before publishing or deploying a build:

- rotate any credential that has ever been committed or shared
- verify no real IP addressing, tokens, passwords, certificates, or private host data need to remain private
- review exposed ports and service bindings
- use least-privilege service accounts
- keep dependencies and container images patched
- validate backups and recovery before relying on stored telemetry

## Public-release status

**Portfolio / active hardening.** The architecture is substantial enough to publish as a security-engineering project, but the repository is not yet release-certified.

The previously tracked Python virtual environment has been removed from the release branch and ignore rules now prevent it from returning. Remaining hardening work is focused on automated security/test gates, installation/recovery documentation, and verifying that example configuration cannot be mistaken for production-safe defaults.

## Public-release checklist

- [x] Remove tracked virtual environment/build artifacts
- [x] Ignore future virtual environments, caches, and local environment files
- [ ] Secret and dependency scanning
- [ ] Automated tests for core ingestion/processing paths
- [ ] Container/config validation
- [ ] Secure-default review
- [ ] Installation and rollback documentation
- [ ] Screenshot/demo material that contains no private infrastructure data
- [ ] CI required before merge

## Support

If this project is useful as a learning or home-lab reference, you can support continued development here:

**Buy Me a Coffee:** https://buymeacoffee.com/divclass016

## Responsible use

Use NetGuard only on systems and networks you own or are explicitly authorized to monitor. Do not use the project to intercept, collect, or analyze traffic without permission.
