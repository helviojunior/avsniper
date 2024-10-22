#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import errno
import os, sys
import sqlite3
from enum import Enum
from pathlib import Path

from .util.logger import Logger
from .__meta__ import __version__, __title__, __author__, __description__, __url__
from .util.sniperdb import SniperDB



class Configuration(object):

    class StrategyEnum(Enum):
        Unknown = 0
        Direct = 1
        Reversed = 2

    version = '0.0.0'
    name = ""

    initialized = False # Flag indicating config has been initialized
    verbose = 0
    filename = None
    cmd_line = ''
    path = ''
    db_name = ''
    is_atty = True
    module = None
    lib_path = ''
    exit_code = 0

    @staticmethod
    def initialize():
        '''
            Sets up default initial configuration values.
            Also sets config values based on command-line arguments.
        '''

        Configuration.version = str(__version__)
        Configuration.name = "AV Sniper"

        Configuration.lib_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'libs')
        
        # Only initialize this class once
        if Configuration.initialized:
            return

        Configuration.initialized = True

        Configuration.verbose = 0 # Verbosity level.
        Configuration.print_stack_traces = True

        # Overwrite config values with arguments (if defined)
        Configuration.load_from_arguments()

    @staticmethod
    def load_from_arguments():
        ''' Sets configuration values based on Argument.args object '''
        from .args import Arguments

        if any(['--version' in word for word in sys.argv]):
            Logger.pl(f' {Configuration.name} v{Configuration.version}\n')
            sys.exit(0)

        args = Arguments()

        a1 = sys.argv
        a1[0] = 'avsniper'
        for a in a1:
            Configuration.cmd_line += "%s " % a

        module = args.get_module()

        if module is None:
            Configuration.mandatory()

        Configuration.verbose = args.args.v

        try:
            from .util.tools import Tools
            Tools.get_mime(__file__)
        except ImportError:
            Logger.pl('{!} {R}error: failed to find libmagic. Check your installation{W}\r\n')
            Logger.pl('     {O}Linux: apt-get install libmagic-dev{W}')
            Logger.pl('     {O}MacOS: brew install libmagic{W}')
            Logger.pl('     {O}Windows: python -m pip install -U python-magic-bin>=0.4.14 --force{W}')
            exit(1)
        except Exception:
            Logger.pl('{!} {R}error: failed to find libmagic. Check your installation{W}\r\n')
            Logger.pl('     {O}Linux: apt-get install libmagic-dev{W}')
            Logger.pl('     {O}MacOS: brew install libmagic{W}')
            Logger.pl('     {O}Windows: python -m pip install -U python-magic-bin>=0.4.14 --force{W}')
            exit(1)

        Logger.pl('{+} {W}Startup parameters')
        Logger.pl('     {C}command line:{O} %s{W}' % Configuration.cmd_line)

        if Configuration.verbose > 0:
            Logger.pl('     {C}verbosity level:{O} %s{W}' % Configuration.verbose)

        Logger.pl('     {C}module:{O} %s{W}' % module.name)

        Configuration.verbose = args.args.v
        Configuration.path = args.args.path

        Configuration.is_atty = os.isatty(sys.stdout.fileno())

        if Configuration.path is None or Configuration.path.strip() == '':
            Logger.pl('{!} {R}error: path is invalid {O}%s{R} {W}\r\n' % (
                args.args.config_file))
            exit(1)

        Configuration.db_name = os.path.join(Configuration.path, 'sniper.db')

        if not module.load_from_arguments(args.args):
            Configuration.mandatory()

        if not os.path.isdir(Configuration.path):
            Logger.pl('{!} {R}error: path does not exists {O}%s{R} {W}\r\n' % (
                Configuration.path))
            exit(1)

        try:
            Configuration.path = os.path.join(Configuration.path, 'bin')
            if not os.path.exists(Configuration.path):
                os.mkdir(Configuration.path)
        except Exception as e:
            Logger.pl('{!} {R}error: could not create {O}bin{R} directory{W}\r\n')
            raise e

        Configuration.module = module

        if module.check_database:
            Configuration.module.open_db(args=args.args, check=True)

    @staticmethod
    def mandatory():
        Logger.pl('{!} {R}error: missing a mandatory option, use -h help{W}\r\n')
        exit(1)

    @staticmethod
    def get_banner():
        Configuration.version = str(__version__)

        return '''\

{G}%s {D}v%s{W}{G} by %s{W}
{W}{D}%s{W}
        ''' % (str(__title__), Configuration.version, __author__, __description__)

