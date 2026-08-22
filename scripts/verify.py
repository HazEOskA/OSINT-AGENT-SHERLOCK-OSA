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
    checks.append(("reference_osint_only", all(item["plane"] not in {"CYBER_RANGE", "AGENTIC_OFFENSE"} for item in repositories)))
    skills_registry = json.loads((SRC / "sherlock_osa" / "osint_skills.json").read_text(encoding="utf-8"))
    skills = skills_registry.get("skills", [])
    checks.append(("osint_skill_count_10", len(skills) == 10))
    checks.append(("osint_skill_unique", len({item["id"] for item in skills}) == 10))
    skill_docs = sorted((ROOT / "skills").glob("*/SKILL.md"))
    checks.append(("osint_skill_docs_10", len(skill_docs) == 10))
    checks.append(
        (
            "osint_skill_docs_match_registry",
            {path.parent.name for path in skill_docs} == {item["id"] for item in skills},
        )
    )
    checks.append(("engine_pin_documented", "f365360383511fea13cd3f7af36ecbbc720ce38d" in (ROOT / "README.md").read_text(encoding="utf-8")))

    parser = UiContractParser()
    parser.feed((SRC / "sherlock_osa" / "web" / "index.html").read_text(encoding="utf-8"))
    required_ids = {
        "osint-form",
        "query-input",
        "query-kind",
        "api-key",
        "deployment-mode",
        "result",
        "repo-grid",
        "service-status",
        "skill-grid",
        "submit-search",
        "trace-list",
    }
    checks.append(("ui_required_elements", required_ids <= parser.ids))
    checks.append(("ui_external_script_only", parser.external_scripts == 1 and parser.inline_scripts == 0))
    styles = (SRC / "sherlock_osa" / "web" / "styles.css").read_text(encoding="utf-8")
    javascript_source = (SRC / "sherlock_osa" / "web" / "app.js").read_text(encoding="utf-8")
    checks.append(("ui_hidden_contract", "[hidden] { display: none !important; }" in styles))
    checks.append(("ui_osint_flow", "runInvestigation" in javascript_source and "/api/v1/osint/investigate" in javascript_source))
    checks.append(("ui_skill_trace", "renderTrace" in javascript_source and "skill_id" in javascript_source))
    worker_source = (SRC / "sherlock_osa" / "research_worker.py").read_text(encoding="utf-8")
    checks.append(("worker_fixed_argv", "shell=True" not in worker_source and '"/usr/bin/curl"' in worker_source))
    checks.append(("worker_target_lock", 'endswith(".onion")' in worker_source and 'hostname == "ahmia.fi"' in worker_source))
    research_compose = (ROOT / "compose.research.yaml").read_text(encoding="utf-8")
    checks.append(("worker_tor_network", "tor-lane:" in research_compose and "internal: true" in research_compose))
    osint_source = (SRC / "sherlock_osa" / "osint.py").read_text(encoding="utf-8")
    checks.append(("fixed_egress_no_redirects", "_NoRedirectHandler" in osint_source and "build_opener" in osint_source))
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
