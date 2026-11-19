import re

from src.base import BaseVisiter
from src.parser import ast


class OVALASTRewriter(BaseVisiter):
    _subtype_node_name_match = re.compile(r'^\S+:(?P<Subtype>\S+)_(?P<Type>\S+)').match

    def __init__(self, simplify: bool):
        super().__init__()
        self.simplify = simplify

    def visit_value(self, node: ast.ValueNode):
        if 'date' in node.attrs:
            node = ast.DateNode.from_node(node)
            node.subsume_attributes()

            return node

        if 'operation' in node.attrs:
            node = ast.OperationNode.from_node(node)
            node.subsume_attributes()

            return node

        if node.oval_class.endswith('behaviors'):
            return ast.BehaviourNode.from_node(node)

        if node.oval_class == 'affected_cpe_list':
            return self._rewrite_affected_cpe(node)

        subtype_node = self._rewrite_subtype_node(node)

        if subtype_node is not None:
            return subtype_node

        reference_node = self._rewrite_reference_node(node)

        if reference_node is not None:
            return reference_node

        self._visit_children(node)

        return node

    def visit_root(self, node: ast.RootNode):
        self._subsume_oval_definitions(node)
        self._visit_children(node)
        node.parse_sections()

        return node

    def visit_index(self, node: ast.IndexNode):
        self._visit_children(node)
        node.build_index()

        return node

    def visit_generator(self, node: ast.GeneratorNode):
        if self.simplify:
            return None

        node.subsume_children()

        return node

    def visit_metadata(self, node: ast.MetadataNode):
        if self.simplify:
            return None

        self._visit_children(node)
        node.subsume_children()

        return node

    @staticmethod
    def visit_cve(node: ast.CVENode):
        node.subsume_attributes()

        return node

    @staticmethod
    def visit_affected(node: ast.AffectedNode):
        node.subsume_children()

        return node

    def visit_definition(self, node: ast.DefinitionNode):
        self._visit_children(node)
        node.subsume_attributes()
        node.subsume_children()

        return node

    def visit_advisory(self, node: ast.AdvisoryNode):
        self._visit_children(node)
        node.subsume_attributes()
        node.subsume_children()

        return node

    def visit_criteria(self, node: ast.CriteriaNode):
        self._visit_children(node)
        node.subsume_attributes()

        return node

    @staticmethod
    def visit_date(node: ast.DateNode):
        node.subsume_attributes()

        return node

    @staticmethod
    def _rewrite_affected_cpe(node: ast.ValueNode):
        node.value = [item.value for item in node.get_children_by_name('cpe')]
        node.children.clear()

        return node

    def _rewrite_subtype_node(self, node: ast.ValueNode):
        def _rewrite_to_subtype(node_klass: ast.SubtypeNode):
            new_node = node_klass.from_node(node, subtype)
            new_node.children = node.children

            self._visit_children(new_node)
            new_node.subsume_attributes()

            return new_node

        result = self._subtype_node_name_match(node.oval_class)

        if result is None:
            return

        subtype = result.group('Subtype')

        match result:
            case r if r.group('Type') == 'test':
                return _rewrite_to_subtype(ast.TestNode)
            case r if r.group('Type') == 'object' and r.group('Subtype') == 'rpminfo':
                new_node = _rewrite_to_subtype(ast.RPMInfoObjectNode)
                new_node.subsume_children()

                return new_node
            case r if r.group('Type') == 'object' and r.group('Subtype') == 'textfilecontent54':
                new_node = _rewrite_to_subtype(ast.TextFileContentObjectNode)
                new_node.subsume_children()

                return new_node
            case r if r.group('Type') == 'object' and r.group('Subtype') == 'rpmverifyfile':
                new_node = _rewrite_to_subtype(ast.RPMVerifyFileNode)
                new_node.subsume_children()

                return new_node
            case r if r.group('Type') == 'object':
                return _rewrite_to_subtype(ast.ObjectNode)
            case r if r.group('Type') == 'state':
                return _rewrite_to_subtype(ast.StateNode)

    @staticmethod
    def _rewrite_reference_node(node: ast.ValueNode):
        for key, value in node.attrs.items():
            if not key.endswith('_ref'):
                continue

            return ast.ReferenceNode.from_node(
                node,
                reference_id=value,
                reference_type=key.rsplit('_', 1)[0],
            )

    @staticmethod
    def _subsume_oval_definitions(node: ast.RootNode):
        if len(node.children) != 1:
            return

        oval_definitions = node.children[0]

        if oval_definitions.oval_class == 'oval_definitions':
            node.children = oval_definitions.children
