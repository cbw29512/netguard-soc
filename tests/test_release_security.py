import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "enterprise" / "docker-compose.yml").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / "enterprise" / ".env.example").read_text(encoding="utf-8")


class EnterpriseReleaseSecurityTests(unittest.TestCase):
    def test_no_literal_enterprise_credentials(self):
        self.assertNotIn("netguardpassword", COMPOSE.lower())
        assignments = {}
        for raw in COMPOSE.splitlines():
            line = raw.strip()
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key in {
                "DOCKER_INFLUXDB_INIT_PASSWORD",
                "DOCKER_INFLUXDB_INIT_ADMIN_TOKEN",
                "GF_SECURITY_ADMIN_PASSWORD",
            }:
                assignments[key] = value.strip()

        expected = {
            "DOCKER_INFLUXDB_INIT_PASSWORD": "${INFLUXDB_INIT_PASSWORD:?Set INFLUXDB_INIT_PASSWORD in the local environment}",
            "DOCKER_INFLUXDB_INIT_ADMIN_TOKEN": "${INFLUXDB_INIT_ADMIN_TOKEN:?Set INFLUXDB_INIT_ADMIN_TOKEN in the local environment}",
            "GF_SECURITY_ADMIN_PASSWORD": "${GRAFANA_ADMIN_PASSWORD:?Set GRAFANA_ADMIN_PASSWORD in the local environment}",
        }
        self.assertEqual(assignments, expected)

    def test_required_secrets_fail_closed(self):
        for variable in (
            "INFLUXDB_INIT_PASSWORD",
            "INFLUXDB_INIT_ADMIN_TOKEN",
            "GRAFANA_ADMIN_PASSWORD",
        ):
            self.assertIn("${" + variable + ":?", COMPOSE)

    def test_service_ports_are_loopback_by_default(self):
        self.assertIn('"127.0.0.1:8086:8086"', COMPOSE)
        self.assertIn('"127.0.0.1:3000:3000"', COMPOSE)
        self.assertNotIn('"8086:8086"', COMPOSE)
        self.assertNotIn('"3000:3000"', COMPOSE)

    def test_container_images_are_not_floating_latest(self):
        self.assertNotRegex(COMPOSE, r"image:\s*[^\n]*:latest(?:\s|$)")
        self.assertIn("influxdb:2.7", COMPOSE)
        self.assertIn("grafana/grafana:13.2", COMPOSE)

    def test_grafana_public_signup_is_disabled(self):
        self.assertIn('GF_USERS_ALLOW_SIGN_UP: "false"', COMPOSE)

    def test_env_template_contains_no_secret_values(self):
        values = {}
        for raw in ENV_EXAMPLE.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value
        for key in (
            "INFLUXDB_INIT_PASSWORD",
            "INFLUXDB_INIT_ADMIN_TOKEN",
            "GRAFANA_ADMIN_PASSWORD",
        ):
            self.assertIn(key, values)
            self.assertEqual(values[key], "")

    def test_install_and_recovery_runbooks_exist(self):
        self.assertTrue((ROOT / "docs" / "INSTALL.md").is_file())
        self.assertTrue((ROOT / "docs" / "RECOVERY.md").is_file())


if __name__ == "__main__":
    unittest.main()
