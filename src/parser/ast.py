from abc import ABCMeta
from collections import defaultdict


class BaseNode:
    SUBSUMABLE_CHILDREN = ()
    _REPR_ATTRS = ()

    __slots__ = ('oval_class', 'parent', 'attrs', 'children',)

    def __init__(self, oval_class: str, parent: 'BaseNode', attrs):
        self.oval_class = oval_class
        self.parent = parent
        self.attrs = dict(attrs)

        self.children = []

    def __repr__(self):
        return f'{self.__class__.__name__}({self._attrs_to_string()})'

    def __hash__(self):
        return hash((self.__class__.__name__, *self.__slots__))

    @classmethod
    def from_node(cls, node: 'BaseNode'):
        return cls(oval_class=node.oval_class, parent=node.parent, attrs=node.attrs)

    def dump(self) -> dict:
        base = {'class': self.oval_class}
        base.update(self.attrs)
        base.update({'children': [child.dump() for child in self.children]})

        return base

    def dump_simplified(self) -> dict:
        base = {'class': self.oval_class}
        base.update(self.attrs)

        return base

    def try_simplified(self):
        if hasattr(self, 'dump_simplified'):
            return self.dump_simplified()

        return self.dump()

    def get_children_by_name(self, key: str) -> list['BaseNode']:
        return [item for item in self.children if item.oval_class == key]

    def repr_tree(self):
        indent = '   '
        mid_connector = '├──'
        closing_connector = '└──'
        continuation_connector = '│  '

        def _walk(node, is_closing, prefix=''):
            if is_closing:
                print(f'{prefix}{closing_connector}{node}')
                prefix += indent
            else:
                print(f'{prefix}{mid_connector}{node}')
                prefix += continuation_connector

            if not node.children:
                return

            for child in node.children[:-1]:
                _walk(child,False, prefix)

            _walk(node.children[-1], True, prefix)

        _walk(self, is_closing=True)

    def _attrs_to_string(self):
        return ', '.join(f'{item}=\"{getattr(self, item, '')}\"' for item in self._REPR_ATTRS)


class SubsumerMixin(BaseNode, metaclass=ABCMeta):
    SUBSUMABLE_CHILDREN = ()
    SUBSUMABLE_ATTRIBUTES = ()

    __slots__ = (*SUBSUMABLE_CHILDREN, *SUBSUMABLE_ATTRIBUTES)

    def subsume_children(self):
        child_value_map = {item.oval_class: (num, item) for num, item in enumerate(self.children)}
        to_remove = []

        for child_name in self.SUBSUMABLE_CHILDREN:
            child = child_value_map.get(child_name)

            if child is None:
                continue

            num, result = child

            setattr(self, self.child_name_preprocess(child_name), result.value)
            to_remove.append(num)

        for num in sorted(to_remove, reverse=True):
            self.children.pop(num)

    def subsume_attributes(self):
        for attr_name in self.SUBSUMABLE_ATTRIBUTES:
            setattr(self, self.attr_name_preprocess(attr_name), self.attrs.pop(attr_name, None))

    def dump(self) -> dict:
        base = super().dump()
        base.update({key: getattr(self, key, None) for key in (*self.SUBSUMABLE_CHILDREN, *self.SUBSUMABLE_ATTRIBUTES)})

        return base

    @staticmethod
    def child_name_preprocess(value: str) -> str:
        for prefix in ('ind-def:', 'red-def:'):
            value = value.removeprefix(prefix)

        return value

    @staticmethod
    def attr_name_preprocess(value: str) -> str:
        return value


class ChildrenSearchMixin(BaseNode):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._children = []
        self._children_cache = None

    def add_child(self, child: BaseNode):
        self._children.append(child)

        if self._children_cache is None:
            self._build_cache()
        else:
            self._children_cache[type(child)].append(child)

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, other):
        self._children = other
        self._build_cache()

    def _build_cache(self):
        self._children_cache = defaultdict(list)

        for child in self.children:
            self._children_cache[type(child)].append(child)

    def find_children_by_type(self, node_type: type[BaseNode]):
        if self._children_cache is None:
            self._build_cache()

        return self._children_cache.get(node_type, [])

    def find_children_by_many(self, *types: type[BaseNode]):
        result = []

        for type_ in types:
            result.extend(self.find_children_by_type(type_))

        return result


class RootNode(BaseNode):
    _REPR_ATTRS = ('oval_class', )

    __slots__ = ('generator', 'definitions', 'tests', 'states', 'objects', )

    def __init__(self, oval_class: str):
        super().__init__(oval_class=oval_class, parent=None, attrs={})

    def parse_sections(self):
        children_map = {item.oval_class: item for item in self.children}

        for section_key in self.__slots__:
            section = children_map.get(section_key)

            if section is None:
                continue

            setattr(self, section_key, section)


class ValueNode(BaseNode):
    _REPR_ATTRS = ('oval_class', 'value', )

    __slots__ = ('value', )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.value = ''

    @classmethod
    def from_node(cls, node: 'ValueNode'):
        new_node = cls(oval_class=node.oval_class, parent=node.parent, attrs=node.attrs)
        new_node.value = node.value

        return new_node

    def dump(self) -> dict:
        base = super().dump()
        base.update(value=self.value)

        return base

    def dump_simplified(self) -> dict:
        base = super().dump_simplified()
        base.update(value=self.value)

        return base


class GeneratorNode(SubsumerMixin):
    SUBSUMABLE_CHILDREN = (
        'product_name',
        'product_version',
        'schema_version',
        'timestamp',
        'content_version',
    )
    _REPR_ATTRS = ('product_name', 'schema_version', 'timestamp', )

    __slots__ = SUBSUMABLE_CHILDREN


class DateNode(SubsumerMixin):
    SUBSUMABLE_ATTRIBUTES = ('date', )
    _REPR_ATTRS = ('oval_class', 'date', )

    __slots__ = SUBSUMABLE_ATTRIBUTES


class CVENode(SubsumerMixin, ValueNode):
    SUBSUMABLE_ATTRIBUTES = ('cvss3', 'cwe', 'href', 'impact', )
    _REPR_ATTRS = ('value', 'cvss3', )

    __slots__ = SUBSUMABLE_ATTRIBUTES


class MetadataNode(SubsumerMixin):
    SUBSUMABLE_CHILDREN = ('title', 'description', )
    _REPR_ATTRS = ('title', )

    __slots__ = SUBSUMABLE_CHILDREN


class AffectedNode(SubsumerMixin):
    SUBSUMABLE_CHILDREN = ('platform', 'product', )
    _REPR_ATTRS = SUBSUMABLE_CHILDREN

    __slots__ = SUBSUMABLE_CHILDREN


class BehaviourNode(BaseNode):
    __slots__ = ()


class DefinitionNode(ChildrenSearchMixin, SubsumerMixin):
    SUBSUMABLE_ATTRIBUTES = ('class', 'id', )
    _REPR_ATTRS = SUBSUMABLE_ATTRIBUTES

    __slots__ = SUBSUMABLE_ATTRIBUTES

    def dump_simplified(self):
        test_nodes = self.find_children_by_type(CriteriaNode)

        return {
            'id': self.id,
            'tests': test_nodes[0].try_simplified() if test_nodes else {}
        }


class AdvisoryNode(SubsumerMixin):
    SUBSUMABLE_ATTRIBUTES = ('from', )
    SUBSUMABLE_CHILDREN = ('affected_cpe_list', 'severity', 'rights', )
    _REPR_ATTRS = SUBSUMABLE_ATTRIBUTES

    __slots__ = (*SUBSUMABLE_CHILDREN, *SUBSUMABLE_ATTRIBUTES)


class CriteriaNode(SubsumerMixin):
    SUBSUMABLE_ATTRIBUTES = ('operator', )
    _REPR_ATTRS = SUBSUMABLE_ATTRIBUTES

    __slots__ = SUBSUMABLE_ATTRIBUTES

    def dump_simplified(self) -> dict:
        return {
            'operator': self.operator,
            'cases:': [item.try_simplified() for item in self.children]
        }


class OperationNode(SubsumerMixin, ValueNode):
    SUBSUMABLE_ATTRIBUTES = ('operation',)
    _REPR_ATTRS = ('oval_class', 'operation', 'value',)

    __slots__ = SUBSUMABLE_ATTRIBUTES

    def dump_simplified(self):
        return {
            'class': self.oval_class,
            'operation': self.operation,
            'value': self.value,
        }


class SubtypeNode(SubsumerMixin):
    SUBSUMABLE_ATTRIBUTES = ('id', )
    _REPR_ATTRS = ('id', 'subtype', )

    __slots__ = _REPR_ATTRS

    def __init__(self, *args, subtype: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.subtype = subtype

    @classmethod
    def from_node(cls, node: 'BaseNode', subtype: str = ''):
        return cls(oval_class=node.oval_class, parent=node.parent, attrs=node.attrs, subtype=subtype)


class TestNode(ChildrenSearchMixin, SubtypeNode):
    SUBSUMABLE_ATTRIBUTES = ('id', 'check', 'check_existence', 'state_operator', )
    _REPR_ATTRS = ('subtype', *SUBSUMABLE_ATTRIBUTES, )

    __slots__ = SUBSUMABLE_ATTRIBUTES

    def dump_simplified(self) -> dict:
        target_nodes = self.find_children_by_many(
            ObjectNode,
            RPMInfoObjectNode,
            RPMVerifyFileNode,
            TextFileContentObjectNode
        )

        return {
            'id': self.id,
            'check_existence': self.check_existence or 'at_least_one_exists',
            'check': self.check,
            'state_operator': self.state_operator or 'AND',
            'object': target_nodes[0].try_simplified() if target_nodes else {},
            'states': [item.try_simplified() for item in self.find_children_by_type(StateNode)]
        }


class ObjectNode(SubtypeNode):
    __slots__ = ()

    def dump_simplified(self) -> dict:
        return {
            'id': self.id,
            'class': self.oval_class,
            'conditions': [item.try_simplified() for item in self.children],
        }


class RPMInfoObjectNode(ObjectNode):
    SUBSUMABLE_CHILDREN = ('red-def:name', )
    _REPR_ATTRS = ('name', )

    __slots__ = _REPR_ATTRS

    def dump_simplified(self) -> dict:
        return {
            'id': self.id,
            'class': self.oval_class,
            'name': self.name,
        }


class RPMVerifyFileNode(ChildrenSearchMixin, ObjectNode):
    SUBSUMABLE_CHILDREN = ('red-def:filepath', )
    _REPR_ATTRS = ('filepath', )

    __slots__ = _REPR_ATTRS

    def dump_simplified(self) -> dict:
        base = {
            'id': self.id,
            'class': self.oval_class,
            'filepath': self.filepath,
        }

        for operation_child in self.find_children_by_type(OperationNode):
            base.update({self.child_name_preprocess(operation_child.oval_class): operation_child.try_simplified()})

        behavior = self.find_children_by_type(BehaviourNode)

        if behavior:
            base.update(behaviors=behavior[0].try_simplified())

        return base


class TextFileContentObjectNode(ChildrenSearchMixin, ObjectNode):
    SUBSUMABLE_CHILDREN = (
        'ind-def:filepath',
        'ind-def:filename',
        'ind-def:path',
        'ind-def:instance'
    )
    _REPR_ATTRS = ('filepath', 'filename', 'path', 'instance', )

    __slots__ = _REPR_ATTRS

    def dump_simplified(self) -> dict:
        base = {
            'id': self.id,
            'class': self.oval_class,
        }
        for attr_name in self._REPR_ATTRS:
            attr = getattr(self, attr_name, None)

            if attr is None:
                continue

            base.update({attr_name: attr})

        behavior = self.find_children_by_type(BehaviourNode)

        if behavior:
            base.update(behaviors=behavior[0].try_simplified())

        pattern = self.find_children_by_type(OperationNode)

        if pattern:
            base.update(pattern=pattern[0].try_simplified())

        return base


class StateNode(SubtypeNode):
    SUBSUMABLE_ATTRIBUTES = ('id', 'operator',)
    _REPR_ATTRS = ('subtype', *SUBSUMABLE_ATTRIBUTES,)

    __slots__ = SUBSUMABLE_ATTRIBUTES

    def dump_simplified(self) -> dict:
        return {
            'id': self.id,
            'class': self.oval_class,
            'operator': self.operator or 'AND',
            'checks': [item.try_simplified() for item in self.children],
        }


class IndexNode(BaseNode):
    __slots__ = ('index', )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.index = {}

    def __repr__(self):
        return f'{self.__class__.__name__}(oval_class="{self.oval_class}", len={self.__len__()})'

    def __len__(self):
        return len(self.index)

    def __contains__(self, item):
        return item in self.index

    def __getitem__(self, item):
        if isinstance(item, slice):
            return tuple(self.index.values())[item]

        return self.index[item]

    def get(self, key, default=None):
        return self.index.get(key, default)

    def build_index(self):
        self.index = {child.id: child for child in self.children if hasattr(child, 'id')}


class ReferenceNode(BaseNode):
    def __init__(self, *args, reference_type: str, reference_id: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = reference_type
        self.id = reference_id

    def __repr__(self):
        return f'{self.__class__.__name__}(type="{self.type}", id="{self.id}")'

    @classmethod
    def from_node(cls, node: 'BaseNode', reference_type: str = '', reference_id: str = ''):
        return cls(
            oval_class=node.oval_class,
            parent=node.parent,
            attrs=node.attrs,
            reference_type=reference_type,
            reference_id=reference_id
        )


class TestCaseNode(BaseNode):
    def __repr__(self):
        return f'{self.__class__.__name__}(oval_class="{self.oval_class}")'

    def dump_simplified(self) -> dict:
        return {
            'id': self.oval_class,
            'tests': [item.try_simplified() for item in self.children],
        }
