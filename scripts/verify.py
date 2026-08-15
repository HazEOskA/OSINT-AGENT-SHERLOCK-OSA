from __future__ import annotations

import compileall
import json
import os
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


class UiContractParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.external_scripts = 0
        self.inline_scripts = 0
        self._inside_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(str(attributes["id"]))
        if tag == "script":
            if attributes.get("src"):
                self.external_scripts += 1
            else:
                self._inside_inline_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inside_inline_script:
            self.inline_scripts += 1
            self._inside_inline_script = False


def main() -> int:
    checks: list[tuple[str, bool]] = []
    checks.append(("compileall", compileall.compile_dir(SRC, quiet=1)))

    reference_file = SRC / "sherlock_osa" / "reference_repos.json"
    benchmark = json.loads(reference_file.read_text(encoding="utf-8"))
    repositories = benchmark.get("repositories", [])
    checks.append(("reference_count_20", len(repositories) == 20))
    checks.append(("reference_unique", len({item["name"] for item in repositories}) == 20))
    checks.append(("engine_pin_documented", "f365360383511fea13cd3f7af36ecbbc720ce38d" in (ROOT / "README.md").read_text(encoding="utf-8")))

    parser = UiContractParser()
    parser.feed((SRC / "sherlock_osa" / "web" / "index.html").read_text(encoding="utf-8"))
    required_ids = {
        "mission-form",
        "api-key",
        "deployment-mode",
        "result",
        "repo-grid",
        "service-status",
        "submit-flow",
    }
    checks.append(("ui_required_elements", required_ids <= parser.ids))
    checks.append(("ui_external_script_only", parser.external_scripts == 1 and parser.inline_scripts == 0))
    node = shutil.which("node")
    if node:
        javascript = subprocess.run(
            [node, "--check", str(SRC / "sherlock_osa" / "web" / "app.js")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        checks.append(("javascript_syntax", javascript.returncode == 0))

    vercel_config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    checks.append(("vercel_python_entrypoint", vercel_config["builds"][0]["src"] == "api/index.py"))
    checks.append(("vercel_catch_all_route", vercel_config["routes"][0]["src"] == "/.*"))

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(SRC)
    tests = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        env=environment,
        check=False,
    )
    checks.append(("unittest", tests.returncode == 0))

    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    return 0 if all(passed for _, passed in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
