from spdx_tools.spdx.model import Document


class RuleCheckFailException(RuntimeError):
    pass


class Rule(object):
    def key(self) -> str:
        raise NotImplementedError

    def apply(self, doc_a: Document, doc_b: Document) -> bool:
        raise NotImplementedError
