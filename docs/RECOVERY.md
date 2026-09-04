# NetGuard SOC Recovery and Rollback

## Credential exposure

If a password, token, private key, or provider credential is committed, copied into an issue/log, or otherwise exposed:

1. Treat it as compromised immediately.
2. Revoke or rotate it at the service that issued it.
3. Replace the local secret in the untracked environment/secrets location.
4. Confirm dependent services reconnect with the new credential.
5. Remove the value from the current tree.
6. Decide whether repository-history cleanup is warranted. History rewriting does not replace credential rotation.

NetGuard previously contained lab credentials in tracked configuration. Do not reuse historical values, even if they have since been deleted from the current tree.

## Application rollback

For a source-code regression:

1. Stop the affected service.
2. Preserve `/var/lib/netguard` and any other mutable state before changing versions.
3. Check out the last known-good Git commit.
4. Revalidate configuration and required secret files.
5. Restart only the affected service and verify logs/health before restoring the rest of the stack.

Do not delete or roll back telemetry databases merely to undo an application-code change.

## Enterprise stack rollback

Before changing Grafana or InfluxDB image versions:

1. Record the currently running image identifiers.
2. Back up persistent data and configuration.
3. Validate that the target version supports the current data format and migration path.
4. Change the image tag deliberately in the local environment or reviewed Compose source.
5. Start the stack and verify health, authentication, dashboards, and data access.

If the new version fails, restore the previous image version first. Restore persistent data only when the data itself was migrated or damaged and a verified backup is required.

## Backup verification

A backup is not considered usable until a restore procedure has been tested on a disposable host or isolated environment. Keep recovery credentials separate from the repository.
