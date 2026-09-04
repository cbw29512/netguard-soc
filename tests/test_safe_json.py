import json
import pathlib
import tempfile
import unittest

from sensors.lib.safe_json import atomic_json_write, read_json_safe


class SafeJsonTests(unittest.TestCase):
    def test_atomic_write_round_trip_and_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "nested" / "state.json"
            atomic_json_write(path, {"status": "first", "count": 1})
            self.assertEqual(read_json_safe(path), {"status": "first", "count": 1})

            atomic_json_write(path, {"status": "second", "count": 2})
            self.assertEqual(read_json_safe(path), {"status": "second", "count": 2})
            leftovers = list(path.parent.glob(".tmp_*.json"))
            self.assertEqual(leftovers, [])

    def test_missing_file_returns_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "missing.json"
            self.assertEqual(read_json_safe(missing, default={"safe": True}), {"safe": True})

    def test_invalid_json_returns_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "broken.json"
            path.write_text("{not-json", encoding="utf-8")
            self.assertEqual(read_json_safe(path, default=[]), [])

    def test_written_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "state.json"
            atomic_json_write(path, {"devices": ["router", "sensor"]})
            with path.open("r", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["devices"], ["router", "sensor"])


if __name__ == "__main__":
    unittest.main()
