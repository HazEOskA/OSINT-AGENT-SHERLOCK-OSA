"""P0.2 OSINT4ALL catalog: offline-only contracts; no external collection."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from sherlock_osa import world_atlas as atlas


class WorldAtlasCatalogTests(unittest.TestCase):
    def test_osint4all_mirror_is_registered_as_catalog_source(self):
        sources = {name: (kind, url) for name, kind, url in atlas._SOURCES}
        self.assertIn("OSINT4ALL", sources)
        self.assertEqual(sources["OSINT4ALL"][0], "markdown")
        self.assertEqual(
            sources["OSINT4ALL"][1],
            "https://raw.githubusercontent.com/osint4all/osint4all.github.io/main/README.md",
        )

    def test_osint4all_markdown_links_are_catalog_only(self):
        text = (
            "## TOOLSET\n"
            "[CyberChef](https://gchq.github.io/CyberChef/)\n"
            "[Unsafe scheme](javascript:alert(1))\n"
            "## HASH RECOVERY\n"
            "[Password crack search](https://example.org/unsafe)\n"
        )
        entries = atlas._parse_markdown(text, "OSINT4ALL")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].category, "TOOLSET")
        self.assertEqual(entries[0].to_dict()["execution_class"], "CATALOG_ONLY")
        self.assertEqual(
            entries[1].to_dict()["execution_class"], "CATALOG_ONLY_RESTRICTED"
        )
        self.assertEqual(entries[0].to_dict()["sources"], ["OSINT4ALL"])

    def test_duplicate_urls_preserve_all_source_provenance(self):
        first = atlas.AtlasTool(
            "CyberChef", "https://gchq.github.io/CyberChef/",
            "Short", "TOOLSET", "OSINT4ALL"
        )
        second = atlas.AtlasTool(
            "CyberChef", "https://gchq.github.io/CyberChef",
            "A longer description", "Security", "Awesome OSINT"
        )
        result = atlas._dedupe([first, second])
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0].to_dict()["sources"], ["OSINT4ALL", "Awesome OSINT"]
        )
        self.assertEqual(
            result[0].to_dict()["categories"], ["TOOLSET", "Security"]
        )
        self.assertEqual(result[0].description, "A longer description")

    def test_catalog_contract_marks_failed_source_without_fake_success(self):
        item = atlas.AtlasTool(
            "Example", "https://example.org/tool", "", "Utilities", "Awesome OSINT"
        )
        with patch.object(
            atlas, "_catalog", return_value=((item,), {"OSINT4ALL": "unavailable"})
        ):
            payload = atlas.atlas_catalog()
        self.assertEqual(payload["version"], "world-atlas-catalog.v1")
        self.assertEqual(payload["tool_count"], 1)
        self.assertFalse(payload["catalog_entries_auto_executed"])
        self.assertEqual(payload["tools"][0]["execution_class"], "CATALOG_ONLY")
        source = next(x for x in payload["sources"] if x["name"] == "OSINT4ALL")
        self.assertEqual(source["status"], "ERROR")
        self.assertEqual(source["error"], "unavailable")

    def test_cached_catalog_keeps_sync_errors(self):
        def fake_fetch(url):
            if "osint4all.github.io" in url:
                raise RuntimeError("simulated external source outage")
            if url.endswith(".json"):
                return json.dumps({
                    "name": "OSINT Framework", "type": "folder",
                    "children": [{
                        "name": "CyberChef", "type": "url",
                        "url": "https://gchq.github.io/CyberChef"
                    }]
                })
            return "## TOOLS\n[CyberChef](https://gchq.github.io/CyberChef/)\n"

        with patch.object(atlas, "_CACHE_TOOLS", ()), \
             patch.object(atlas, "_CACHE_AT", 0.0), \
             patch.object(atlas, "_CACHE_ERRORS", {}), \
             patch.object(atlas, "_fetch_text", side_effect=fake_fetch) as fetch:
            first, errors1 = atlas._catalog()
            second, errors2 = atlas._catalog()
            self.assertEqual(len(first), 1)
            self.assertEqual(second, first)
            self.assertIn("OSINT4ALL", errors1)
            self.assertEqual(errors1, errors2)
            self.assertEqual(fetch.call_count, len(atlas._SOURCES))

    @unittest.skipUnless(shutil.which("node"), "Node is unavailable")
    def test_atlas_javascript_syntax(self):
        path = Path(__file__).resolve().parents[1] / "src/sherlock_osa/web/atlas.js"
        result = subprocess.run(
            ["node", "--check", str(path)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
