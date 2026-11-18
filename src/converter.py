import json
import pdb
from pathlib import Path
from argparse import ArgumentParser

from src.parser.xml_parser import OVALParser
from src.parser.rewriter import OVALASTRewriter
from src.resolver import OVALDefinitionResolver


class OVALConverter:
    def __init__(self):
        self._args = self._parse_arguments()

        self._parser = OVALParser()
        self._rewriter = OVALASTRewriter(
            simplify=self._args.convert,
            naming_template=self._args.template,
            convert_dnf=self._args.dnf,
        )
        self._resolver = OVALDefinitionResolver()
        self._filepath = self._resolve_filepath(self._args.filepath)

    def convert(self):
        root = self._parser.parse(str(self._filepath))
        rewritten_root = self._rewriter.run(root)

        self._resolver.configure(root)

        result = []

        for definition in self._collect_targets(rewritten_root):
            resolved = self._resolver.resolve(definition)

            result.append(resolved.dump_simplified() if self._args.convert else resolved.dump())

        self._dump_json(result)

        if self._args.pdb:
            pdb.set_trace()

        return 0

    def _dump_json(self, value):
        destination = self._resolve_filepath(self._args.output_file or self._filepath.name).with_suffix('.json')

        with open(destination, 'w') as f:
            json.dump(value, f, ensure_ascii=False, indent=None if self._args.no_format else 4)

    def _collect_targets(self, root):
        targets = set(root.definitions[:self._args.count])

        for item in self._args.id:
            targets.add(root.definitions[item])

        return targets

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

        return parser.parse_args()

    @staticmethod
    def _resolve_filepath(value: str) -> Path:
        path = Path(value)

        if path.is_absolute():
            return path

        return Path.cwd() / path
