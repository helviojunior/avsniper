#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from argparse import _ArgumentGroup, Namespace

from .cmdbase import CmdBase
from .util.color import Color

import argparse, sys, os


class Arguments(object):
    ''' Holds arguments used by the KnowsMore '''
    modules = {}
    verbose = False
    args = None

    def __init__(self):
        self.verbose = any(['-v' in word for word in sys.argv])
        self.args = self.get_arguments()

    def _verbose(self, msg):
        if self.verbose:
            Color.pl(msg)

    @classmethod
    def get_module(cls):
        if len(Arguments.modules) == 0:
            Arguments.modules = CmdBase.list_modules()

        selected_modules = [
            mod for mod in Arguments.modules
            if any([f'--{mod}' == word.lower() for word in sys.argv])
        ]

        if len(selected_modules) > 1:
            Color.pl('{!} {R}error: missing a mandatory option, use -h help{W}\r\n')
            exit(1)

        mod = None
        if len(selected_modules) == 1:
            mod = Arguments.modules[selected_modules[0]].create_instance()

        return mod

    def get_arguments(self) -> Namespace:
        ''' Returns parser.args() containing all program arguments '''

        parser = argparse.ArgumentParser(
            usage=argparse.SUPPRESS,
            prog="AVSniper",
            add_help=False,
            epilog='Use "avsniper projet_path [module] --help" for more information about a command.',
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80, width=130))

        parser.add_argument('path',
                            action='store',
                            metavar='[project path]',
                            type=str,
                            help=Color.s('Project path'))

        mod = self.get_module()

        modules_group = parser.add_argument_group('Available Modules')
        self._add_modules(modules_group, mod)

        if mod is not None:
            commands_group = parser.add_argument_group('Available Module Commands')
            mod.add_commands(commands_group)

            mod.add_groups(parser)

            flags = parser.add_argument_group('Module Flags')
            mod.add_flags(flags)

        flags = parser.add_argument_group('Global Flags')
        self._add_flags_args(flags)

        parser.usage = self.get_usage(module=mod)

        return parser.parse_args()

    def _add_flags_args(self, flags: _ArgumentGroup):
        flags.add_argument('-h', '--help',
                           action='help',
                           help=Color.s('Show help message and exit'))

        flags.add_argument('-v',
                           action='count',
                           default=0,
                           help=Color.s(
                               'Specify verbosity level (default: {G}0{W}). Example: {G}-v{W}, {G}-vv{W}, {G}-vvv{W}'
                           ))

        flags.add_argument('--version',
                           action='store_true',
                           default=False,
                           dest=f'version',
                           help=Color.s('Show current version'))

    def _add_modules(self, modules_group: _ArgumentGroup, module: CmdBase = None):
        for m in Arguments.modules:
            help = Color.s(f'{Arguments.modules[m].description}')
            if module is not None:
                help = argparse.SUPPRESS
            modules_group.add_argument(f'--{m}',
                                       action='store_true',
                                       help=help)

    def get_usage(self, module: CmdBase = None):
        if module is None:
            return f'''
    avsniper projet_path module [flags]'''
        else:
            return f'''
    avsniper --{module.name.lower()} command [flags]'''
