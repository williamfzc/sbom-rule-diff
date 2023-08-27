import typing

from spdx_tools.spdx.model import Document

from sbom_rule_diff import Rule, StrictRunner


class ARule(Rule):
    def key(self) -> str:
        return "a_rule"

    def apply(self, doc_a: Document, doc_b: Document) -> bool:
        ver_a = dict()
        ver_b = dict()
        for each in doc_a.packages:
            if each.name.startswith("babel"):
                ver_a[each.name] = each
        for each in doc_b.packages:
            if each.name.startswith("babel"):
                ver_b[each.name] = each

        return abs(len(doc_a.packages) - len(doc_b.packages)) < 10


if __name__ == "__main__":
    runner = StrictRunner()
    runner.add_rule(ARule())
    runner.run_with_file(
        "./sbom-test/bom-pnpm-before.json",
        "./sbom-test/bom-pnpm.json",
    )
