from xml.sax import ContentHandler, parse

from src.parser import ast
from src.utils import strip_oval_name


class OVALBuilderException(Exception):
    pass


class OVALParser(ContentHandler):
    TAG_TABLE = {
        'generator': ast.GeneratorNode,
        'definition': ast.DefinitionNode,
        'metadata': ast.MetadataNode,
        'affected': ast.AffectedNode,
        'advisory': ast.AdvisoryNode,
        'criteria': ast.CriteriaNode,
        'definitions': ast.IndexNode,
        'objects': ast.IndexNode,
        'states': ast.IndexNode,
        'tests': ast.IndexNode,
        'cve': ast.CVENode,
    }

    def __init__(self):
        super().__init__()
        self.root = None

    def parse(self, path: str) -> ast.RootNode:
        self._init_root()
        parse(path, self)

        if not isinstance(self.root, ast.RootNode):
            raise OVALBuilderException(f'Missing end tag {self.root.oval_class}')

        return self.root

    def startElement(self, name: str, attrs: dict):
        self._step_down(name, attrs)

    def endElement(self, *_):
        self._step_up()

    def characters(self, content):
        content = content.strip()

        if not content:
            return

        self.root.value += content

    def _step_down(self, tag: str, attrs: dict):
        name = strip_oval_name(tag)
        node_klass = self.TAG_TABLE.get(name, ast.ValueNode)
        new_node = node_klass(oval_class=name, attrs=attrs, parent=self.root)
        self.root.children.append(new_node)
        self.root = new_node

    def _step_up(self):
        self.root = self.root.parent

    def _init_root(self):
        self.root = ast.RootNode(oval_class='root')
