from pathlib import Path
import unittest
from unittest.mock import patch

from autoreviewer.cli import main


class UiCliTests(unittest.TestCase):
    def test_ui_launches_with_local_defaults(self):
        with patch("autoreviewer.web.serve", return_value=0) as serve:
            self.assertEqual(main(["ui"]), 0)
        serve.assert_called_once_with(Path("autoreviewer.toml"), Path(".autoreviewer/ui"), 8765, False)

    def test_ui_passes_explicit_paths_port_and_open_option(self):
        with patch("autoreviewer.web.serve", return_value=0) as serve:
            self.assertEqual(main(["ui", "--config", "local.toml", "--data-dir", "history", "--port", "8920", "--open"]), 0)
        serve.assert_called_once_with(Path("local.toml"), Path("history"), 8920, True)


if __name__ == "__main__":
    unittest.main()
