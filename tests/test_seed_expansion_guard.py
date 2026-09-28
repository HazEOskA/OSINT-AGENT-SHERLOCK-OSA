from __future__ import annotations

import asyncio
import time
import unittest

from sherlock_osa.research import (
    IdentifierKind,
    ModuleContext,
    ResearchIdentifier,
    SeedExpansionModule,
)


class SeedExpansionStructuralPathTests(unittest.TestCase):
    def _lookup(self, url: str):
        module = SeedExpansionModule()
        context = ModuleContext(
            deadline_monotonic=time.monotonic() + 5,
            allowed_capabilities=frozenset({"osint.correlation.expand"}),
        )
        return asyncio.run(
            module.lookup(
                ResearchIdentifier(IdentifierKind.URL, url),
                context,
            )
        )

    def test_members_path_is_not_promoted_to_username(self) -> None:
        result = self._lookup("https://example.com/members")
        usernames = [
            pivot.value
            for pivot in result.pivots
            if pivot.kind is IdentifierKind.USERNAME
        ]
        self.assertEqual(usernames, [])

    def test_real_username_after_members_path_is_kept(self) -> None:
        result = self._lookup("https://example.com/members/realnick")
        usernames = [
            pivot.value
            for pivot in result.pivots
            if pivot.kind is IdentifierKind.USERNAME
        ]
        self.assertEqual(usernames, ["realnick"])

    def test_direct_username_named_members_is_not_blocked(self) -> None:
        seed = ResearchIdentifier(IdentifierKind.USERNAME, "members")
        self.assertEqual(seed.value, "members")


if __name__ == "__main__":
    unittest.main()
