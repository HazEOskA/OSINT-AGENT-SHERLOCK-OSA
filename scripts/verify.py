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
        self.external_scripts: list[str] = []
        self.inline_scripts = 0
        self._inside_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(str(attributes["id"]))
        if tag == "script":
            src = attributes.get("src")
            if src:
                self.external_scripts.append(str(src))
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
    checks.append((
        "engine_pin_documented",
        "f365360383511fea13cd3f7af36ecbbc720ce38d"
        in (ROOT / "README.md").read_text(encoding="utf-8"),
    ))
    checks.append((
        "emailosint_primary_documented",
        "POST /api/v1/lookup/email" in (ROOT / "README.md").read_text(encoding="utf-8"),
    ))

    parser = UiContractParser()
    parser.feed((SRC / "sherlock_osa" / "web" / "index.html").read_text(encoding="utf-8"))
    required_ids = {
        "search-form",
        "search-kind",
        "search-query",
        "search-submit",
        "search-mode",
        "live-feed",
        "source-runs",
        "timeline-list",
        "identity-list",
        "graph-list",
        "api-key",
        "deployment-mode",
        "result",
        "service-status",
        "accounts-list",
        "breaches-list",
        "stealer-list",
        "findings-list",
        "email-parity-section",
        "email-signals-list",
        "email-breach-parity-list",
        "email-stealer-parity-list",
        "email-ai-headline",
        "email-provider-source-list",
        "result-json",
    }
    checks.append(("ui_required_elements", required_ids <= parser.ids))
    expected_scripts = {"/assets/app.js", "/assets/parity.js"}
    checks.append((
        "ui_external_script_only",
        parser.inline_scripts == 0
        and set(parser.external_scripts) == expected_scripts
        and len(parser.external_scripts) == len(expected_scripts),
    ))

    styles = (SRC / "sherlock_osa" / "web" / "styles.css").read_text(encoding="utf-8")
    parity_styles = (SRC / "sherlock_osa" / "web" / "parity.css").read_text(encoding="utf-8")
    javascript_source = (SRC / "sherlock_osa" / "web" / "app.js").read_text(encoding="utf-8")
    parity_javascript_source = (SRC / "sherlock_osa" / "web" / "parity.js").read_text(encoding="utf-8")
    checks.append(("ui_hidden_contract", "[hidden] { display: none !important; }" in styles))
    checks.append(("ui_primary_lookup_route", '"/api/v1/search/stream"' in javascript_source))
    checks.append(("ui_parity_contract", "renderParity" in parity_javascript_source and ".parity-card" in parity_styles))

    node = shutil.which("node")
    if node:
        js_results = []
        for script in ("app.js", "parity.js"):
            result = subprocess.run(
                [node, "--check", str(SRC / "sherlock_osa" / "web" / script)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            js_results.append(result.returncode == 0)
        checks.append(("javascript_syntax", all(js_results)))

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
