import unittest
from pathlib import Path

from app.services.semgrep_service import SemgrepService


class SemgrepCommandTests(unittest.TestCase):
    def test_uses_explicit_config_with_metrics_disabled(self):
        command = SemgrepService()._build_command(
            Path("semgrep"),
            Path("repository"),
        )

        config_index = command.index("--config")
        self.assertEqual(command[config_index + 1], "p/security-audit")
        self.assertIn("--metrics=off", command)
        self.assertNotIn("auto", command)


if __name__ == "__main__":
    unittest.main()
