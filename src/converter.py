import json
import pdb
from pathlib import Path
from argparse import ArgumentParser
from operator import attrgetter

from src.parser.xml_parser import OVALParser
from src.parser.rewriter import OVALASTRewriter
from src.resolver import OVALDefinitionResolver


class OVALConverter:
    def __init__(self):
        self._args = self._parse_arguments()

        self._parser = OVALParser()
        self._rewriter = OVALASTRewriter(simplify=self._args.convert)
        self._resolver = OVALDefinitionResolver(naming_schema=self._args.template)
        self._filepath = self._resolve_filepath(self._args.filepath)

    def convert(self):
        root = self._parser.parse(str(self._filepath))
        self._rewriter.run(root)

        self._resolver.configure(root)

        if self._args.no_resolve:
            self._convert(root)
        else:
            self._convert_with_resolve(root)

        if self._args.pdb:
            pdb.set_trace()

        return 0

    def _convert_with_resolve(self, root):
        result = []

        for definition in self._collect_targets(root):
            definition = self._resolver.resolve_definition(definition)

            if self._args.dnf:
                definition = self._resolver.criteria_to_dnf(definition)

            result.append(definition.dump_simplified() if self._args.convert else definition.dump())

        self._dump_json(result)

    def _convert(self, root):
        result = []
        tests = []

        for definition in self._collect_targets(root):
            tests.extend(self._resolver.resolve_tests(definition))

            if self._args.dnf:
                definition = self._resolver.criteria_to_dnf(definition)

            result.append(definition.dump_simplified() if self._args.convert else definition.dump())

        tests = {
            item.id: item.dump_simplified() if self._args.convert else item.dump()
            for item in sorted(tests, key=attrgetter('id'))
        }

        self._dump_json({'definitions': result, 'tests': tests})

    def _dump_json(self, value):
        destination = self._resolve_filepath(self._args.output_file or self._filepath.name).with_suffix('.json')

        with open(destination, 'w') as f:
            json.dump(value, f, ensure_ascii=False, indent=None if self._args.no_format else 4)

    def _collect_targets(self, root):
        targets = set(root.definitions[:self._args.count])

        for item in self._args.id:
            targets.add(root.definitions[item])

        return sorted(targets, key=attrgetter('id'))

    @staticmethod
    def _parse_arguments():
        parser = ArgumentParser()

        parser.add_argument('filepath')
        parser.add_argument(
            '-c',
            '--count',
            dest='count',
            type=int,
            default=5,
            help='convert first COUNT definitions'
        )
        parser.add_argument(
            '--id',
            action='append',
            dest='id',
            default=[],
            help='convert definition by id; can be specified multiple times'
        )
        parser.add_argument('-o', '--output', dest='output_file', help='output json file')
        parser.add_argument(
            '--pdb',
            action='store_true',
            default=False,
            help='invoke pdb.set_trace() after results are saved; used for manual tree inspection'
        )
        parser.add_argument(
            '--naming-template',
            dest='template',
            default='oval-converter:{name}:{num}',
            help='naming template for converter-specific nodes; must contain {name} and {num}'
        )
        parser.add_argument(
            '--raw',
            action='store_false',
            dest='convert',
            default=True,
            help='disable convertion to simplified form'
        )
        parser.add_argument(
            '--dnf',
            action='store_true',
            dest='dnf',
            default=False,
            help='convert criteria tree to dnf'
        )
        parser.add_argument(
            '--no-format',
            action='store_true',
            dest='no_format',
            default=False,
            help='do not format output with indentations'
        )
        parser.add_argument(
            '--no-resolve',
            action='store_true',
            dest='no_resolve',
            default=False,
            help='do not resolve criterion references; instead, create a dictionary with resolved tests'
        )

        return parser.parse_args()

    @staticmethod
    def _resolve_filepath(value: str) -> Path:
        path = Path(value)

        if path.is_absolute():
            return path

        return Path.cwd() / path
