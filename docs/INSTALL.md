# NetGuard SOC Installation

NetGuard is an appliance-style Ubuntu lab project. Its documented runtime layout uses `/opt/netguard` for code/configuration and `/var/lib/netguard` for mutable state.

## Before installation

1. Use a dedicated Ubuntu host or VM on a network you are authorized to monitor.
2. Install Docker Engine with the Compose plugin and Python 3.
3. Clone or copy this repository to `/opt/netguard`.
4. Review every interface, sensor, capture source, service port, and retention setting before enabling it.
5. Do not reuse credentials that have ever appeared in repository history.

## Enterprise services

From `/opt/netguard/enterprise`:

```bash
cp .env.example .env
chmod 600 .env
```

Fill these required values with new random secrets:

- `INFLUXDB_INIT_PASSWORD`
- `INFLUXDB_INIT_ADMIN_TOKEN`
- `GRAFANA_ADMIN_PASSWORD`

The committed Compose configuration binds Grafana and InfluxDB to loopback by default. Keep those loopback bindings unless you have deliberately placed the services behind an authenticated reverse proxy or another trusted access-control layer.

Validate the resolved configuration before starting anything:

```bash
docker compose config
```

Then start deliberately:

```bash
docker compose up -d
```

## Runtime state

Mutable telemetry, databases, snapshots, and generated state belong under `/var/lib/netguard` or ignored runtime directories. They are not source artifacts and must not be committed.

## Verification

After installation:

1. Confirm only intended ports are listening (`ss -lntup`).
2. Confirm Grafana and InfluxDB are reachable only through the intended interface/path.
3. Confirm sensors read only authorized interfaces and sources.
4. Check service logs for authentication or permission failures.
5. Verify backups before relying on collected telemetry.

## Updating

Review the repository diff and release notes first. Back up mutable state, validate Compose/configuration, then update code. Do not automatically pull floating container images into a production-like lab.
