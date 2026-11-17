from src.parser import ast


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

    def __init__(self):
        self._store: ast.RootNode = None
        self._cache = ResolverCache()

    def resolve(self, definition: ast.DefinitionNode):
        return self._resolve_node(definition)

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

    def _resolve_and_cache(self, node: ast.ReferenceNode):
        new_node = self._cache.get(node.type, node.id)

        if new_node is None:
            new_node = self._resolve_reference(node)
            self._cache.update(node.type, node.id, new_node)

        return new_node

    def _resolve_reference(self, node: ast.ReferenceNode):
        return getattr(self._store, self.REFERENCE_STORE_MAP.get(node.type, ''), {}).get(node.id, node)
