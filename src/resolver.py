from src.parser import ast
from src.utils import resolve_criteria_to_dnf


class ResolverCache:
    def __init__(self):
        self._store = {
            'test': {},
            'object': {},
            'state': {},
            'definition': {},
        }

    def update(self, section, key, value):
        self._store[section][key] = value

    def get(self, section, key, default=None):
        return self._store[section].get(key, default)


class OVALDefinitionResolver:
    REFERENCE_STORE_MAP = {
        'test': 'tests',
        'object': 'objects',
        'state': 'states',
        'definition': 'definitions'
    }

    def __init__(self, naming_schema: str):
        self._store: ast.RootNode = None
        self._cache = ResolverCache()
        self._naming_schema = naming_schema

    def resolve_definition(self, definition: ast.DefinitionNode):
        return self._resolve_node(definition)

    def resolve_tests(self, definition: ast.DefinitionNode) -> list[ast.TestNode]:
        tests = []

        for test in self._collect_tests(definition):
            tests.append(self._resolve_node(test))

        return tests

    def configure(self, root: ast.RootNode):
        self._store = root

    def _resolve_node(self, node: ast.BaseNode):
        if isinstance(node, ast.ReferenceNode):
            node = self._resolve_and_cache(node)

        resolved_children = []

        for child in node.children:
            resolved_children.append(self._resolve_node(child))

        node.children = resolved_children

        return node

    def _collect_tests(self, node: ast.BaseNode):
        if isinstance(node, ast.ReferenceNode) and node.type == 'test':
            yield node

            return

        for child in node.children:
            yield from self._collect_tests(child)

    def _resolve_and_cache(self, node: ast.ReferenceNode):
        new_node = self._cache.get(node.type, node.id)

        if new_node is None:
            new_node = self._resolve_reference(node)
            self._cache.update(node.type, node.id, new_node)

        return new_node

    def _resolve_reference(self, node: ast.ReferenceNode):
        return getattr(self._store, self.REFERENCE_STORE_MAP.get(node.type, ''), {}).get(node.id, node)

    def criteria_to_dnf(self, node: ast.DefinitionNode):
        new_children = []
        cases = []

        for child in node.find_children_by_type(ast.CriteriaNode):
            cases.extend(resolve_criteria_to_dnf(child))

        dnf_criteria = ast.CriteriaNode(oval_class='tests', parent=node, attrs={})
        dnf_criteria.operator = 'OR'
        new_children.append(dnf_criteria)

        for num, case in enumerate(cases, start=1):
            test_case = ast.TestCaseNode(
                oval_class=self._format_naming_schema(num, 'test_case'),
                parent=dnf_criteria,
                attrs={}
            )
            test_case.children.extend(case)
            dnf_criteria.children.append(test_case)

        node.children = new_children

        return node

    def _format_naming_schema(self, num: int, name: str) -> str:
        return self._naming_schema.format(num=num, name=name)
