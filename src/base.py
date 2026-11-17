import re
from abc import ABCMeta

from src.parser import ast


class BaseVisiter(metaclass=ABCMeta):
    _split_node_name = re.compile(r'(?:[A-Z]{2,}|[A-Z][^A-Z]*)+(?=Node)').findall

    def run(self, node: ast.BaseNode):
        return self._visit_node(node)

    def _visit_node(self, node: ast.BaseNode):
        visit_method = getattr(self, 'visit_' + self._get_node_name(node), None)

        if visit_method is None:
            self._visit_children(node)

            return node

        return visit_method(node)

    def _visit_children(self, node: ast.BaseNode):
        rewritten = []

        for child in node.children:
            new_child = self._visit_node(child)

            if new_child is None:
                continue

            rewritten.append(new_child)

        node.children = rewritten

    @classmethod
    def _get_node_name(cls, node: ast.BaseNode) -> str:
        return '_'.join(cls._split_node_name(node.__class__.__name__)).lower()
