import argparse
import datetime
import errno
import hashlib
import os
import re
import shutil
import sqlite3
import struct
import threading
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from typing import Optional, Union
from os.path import expanduser
from itertools import permutations
from uuid import UUID

import yaml

import hexdump

from avsniper.libs.binary_tree import BinarySearchTree
from avsniper.libs.pyinstaller import PyInstArchive
from avsniper.util.process import Process
from clint.textui import progress

from avsniper.cmd.checkremote import RemoteFile
from avsniper.cmd.enumerate import EnumerateFile
from avsniper.cmd.list import ListStrings
from avsniper.cmd.strip import StripFile
from avsniper.cmd.transfor import TransforBlackListToStrings
from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.cursor import Cursor
from avsniper.util.exerunner import ExeRunner
from avsniper.util.worker import Worker

from avsniper.cmdbase import CmdBase
from avsniper.config import Configuration
from avsniper.util.color import Color
from avsniper.util.logger import Logger
from avsniper.util.sniperdb import SniperDB
from avsniper.util.strings import Strings, StringsEncoding, StringPart
from avsniper.util.tools import Tools


class StripFoundException(Exception):
    pass


class AutoChecker(CmdBase):
    db = None
    order = 5
    check_database = True
    db_path = None
    bkp1 = None
    bkp2 = None
    count = 0
    enumeration_found = None
    files = {}
    av_name = None
    os_info = None
    file_info = {}
    sha256_hash = None
    backup_path = None
    # Parameters
    config_file = None
    file_name = None
    #
    # Config values
    #   General
    tasks = 5
    sleep = 2
    #  Server
    api_url = 'http://127.0.0.1:8080'
    cmd = None
    #  Enum
    min_size = 5
    min_entropy = 1.5
    threshold = 30
    no_dotnet = False
    no_strip = False
    use_raw = False
    cert_only = False
    disable_crashable_string_check = False
    # Step 1
    st1_rounds = 10

    def __init__(self):
        super().__init__('auto-checker', 'Fully automated checker')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--file',
                           action='store',
                           metavar='[PE file path]',
                           type=str,
                           dest=f'pe_file',
                           help=Color.s('Full path of the PE file'))

        flags.add_argument('--config',
                           action='store',
                           metavar='[config file]',
                           type=str,
                           default='./config.yml',
                           dest=f'config_file',
                           help=Color.s('Configuration file. (default: {G}./config.yml{W})'))

        flags.add_argument('--create-config',
                           action='store_true',
                           default=False,
                           dest=f'create_config',
                           help=Color.s('Create config sample'))

        flags.add_argument('--clear-session',
                           action='store_true',
                           default=False,
                           dest=f'clear_session',
                           help=Color.s('Clear old file status and reindex all files'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        self.config_file = args.config_file
        if args.create_config:
            if os.path.isfile(self.config_file):
                Logger.pl(
                    '{!} {R}Error: The configuration already exists.\n'
                )
                exit(1)

            Configuration.initialized = False
            self._create_config()
            exit(0)

        if args.pe_file is None or not os.path.exists(args.pe_file):
            Logger.pl(
                '{!} {R}error: PE file "{O}%s{R}" does not exists{W}\r\n' % args.pe_file)
            exit(1)

        try:
            with open(args.pe_file, 'rb') as f:
                self.file_name = args.pe_file
                f_data = bytearray(f.read())
                self.sha256_hash = hashlib.sha256(f_data).hexdigest().lower()

                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl('{!} {R}error: could not open PE file {O}permission denied{R}{W}\r\n')
                exit(1)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open PE file {O}it is an directory{R}{W}\r\n')
                exit(1)
            else:
                Logger.pl('{!} {R}error: could not open PE file {W}\r\n')
                exit(1)

        try:

            if not os.path.isfile(self.config_file):
                Logger.pl(
                    '{!} {W}The configuration file does not exists.'
                )
                Logger.p(
                    '{!} {W}Do you want create an default file and continue? (Y/n): {W}')
                c = input()
                if c.lower() == 'n':
                    exit(0)
                    Logger.pl(' ')

                self._create_config()

            with open(self.config_file, 'r') as f:
                data = dict(yaml.load(f, Loader=yaml.FullLoader))

                # General
                if data is not None and data.get('general', None) is not None:
                    general = data.get('general', {})

                    self.tasks = int(general.get('tasks', self.tasks))
                    self.sleep = float(general.get('sleep', self.sleep))
                    self.no_strip = Tools.to_boolean(general.get('no_strip', self.no_strip))

                # Enumeration
                if data is not None and data.get('enumeration', None) is not None:
                    enumeration = data.get('enumeration', {})

                    self.min_size = int(enumeration.get('min_size', self.min_size))
                    self.min_entropy = round(float(enumeration.get('min_entropy', self.min_entropy)), 2)
                    self.threshold = int(enumeration.get('threshold', self.threshold))
                    self.no_dotnet = Tools.to_boolean(enumeration.get('no_dotnet', self.no_dotnet))
                    self.use_raw = Tools.to_boolean(enumeration.get('use_raw', self.use_raw))
                    self.cert_only = Tools.to_boolean(enumeration.get('cert_only', self.cert_only))
                    self.disable_crashable_string_check = Tools.to_boolean(
                        enumeration.get('disable_crashable_string_check', self.disable_crashable_string_check))

                    if self.min_size < 3:
                        self.min_size = 3

                    if self.min_entropy < 0:
                        self.min_entropy = 0
                    elif self.min_entropy >= 10:
                        self.min_entropy = 10

                    if self.threshold < 0:
                        self.threshold = 0
                    elif self.threshold >= 100:
                        self.threshold = 100

                # Step 1
                if data is not None and data.get('step1', None) is not None:
                    step1 = data.get('step1', {})

                    self.st1_rounds = int(step1.get('rounds', self.st1_rounds))

                    if self.st1_rounds < 2:
                        self.st1_rounds = 2

                # Server
                if data is not None and data.get('server', None) is not None:
                    server = data.get('server', {})

                    self.api_url = server.get('api_url', self.api_url)
                    self.cmd = server.get('remote_command', self.cmd)

                    if self.cmd is None or self.cmd.strip() == '':
                        self.cmd = None

        except IOError as x:
            if x.errno == errno.EACCES:
                Color.pl('{!} {R}error: could not open {G}%s {O}permission denied{R}{W}\r\n' % self.config_file)
                exit(1)
            elif x.errno == errno.EISDIR:
                Color.pl('{!} {R}error: could not open {G}%s {O}it is an directory{R}{W}\r\n' % self.config_file)
                exit(1)
            else:
                Color.pl('{!} {R}error: could not open {G}%s{W}\r\n' % self.config_file)
                exit(1)

        p_name = Tools.calc_pe_path_name(f_data)

        # General backup path
        self.backup_path = Path(expanduser(f'~/.avsniper/{p_name}/'))

        Configuration.path = os.path.join(Configuration.path, p_name)
        Configuration.db_name = os.path.join(Configuration.path, 'sniper.db')

        if not os.path.isdir(Configuration.path):
            Path(Configuration.path).mkdir(parents=True)

        if not os.path.isdir(Configuration.path):
            Logger.pl('{!} {R}error: path does not exists {O}%s{R} {W}\r\n' % (
                Configuration.path))
            exit(1)

        if args.clear_session or not os.path.isfile(Configuration.db_name):
            if os.path.isfile(Configuration.db_name):
                os.unlink(Configuration.db_name)

            SniperDB(db_name=Configuration.db_name, auto_create=True)

        self.db = self.open_db(args)

        if Configuration.verbose >= 2:
            self.print_config()

        self.db_path = str(Path(Configuration.db_name).resolve().parent)

        self.bkp1 = os.path.join(self.db_path, 'sniper_bkp1.db')
        self.bkp2 = os.path.join(self.db_path, 'sniper_bkp2.db')

        return True

    def print_config(self):
        with open(self.config_file, 'r') as f:
            data = dict(yaml.load(f, Loader=yaml.FullLoader))
            Logger.pl('\n{+} {W}Running config: {W}')
            Logger.pl('{GR}%s{W}' % yaml.dump(data, sort_keys=False, default_flow_style=False))

    def _create_config(self):
        sample_config = self._get_config_sample()

        with open(self.config_file, 'w') as f:
            yaml.dump(sample_config, f, sort_keys=False, default_flow_style=False)

        Logger.pl('{+} {W}Config file created at {O}%s{W}\n' % self.config_file)

    def _get_config_sample(self) -> dict:
        sample_config = {
            'general': {
                'tasks': self.tasks,
                'sleep': round(self.sleep, 2),
                'no_strip': self.no_strip
            },
            'enumeration': {
                'min_size': self.min_size,
                'min_entropy': round(self.min_entropy),
                'threshold': self.threshold,
                'no_dotnet': self.no_dotnet,
                'use_raw': self.use_raw,
                'cert_only': self.cert_only,
                'disable_crashable_string_check': self.disable_crashable_string_check,
            },
            'step1': {
                'rounds': self.st1_rounds,
            },
            'server': {
                'api_url': self.api_url,
                'remote_command': self.cmd if self.cmd is not None else '',
            }
        }

        return sample_config

    def run(self):

        try:
            self.do_initial_check()
            self.do_step1()
            self.do_step2()
            self.do_step3()
            self.do_step4()
            self.do_step5()
            self.do_step4()  # Do again
            self.do_step6()
            self.do_step7()
            self.do_get_list()
            self.do_backup()

        except KeyboardInterrupt as e:
            raise e

    def do_backup(self):
        try:
            if not os.path.isdir(self.backup_path):
                Path(self.backup_path).mkdir(parents=True)

            shutil.copy(Configuration.db_name, os.path.join(self.backup_path, 'sniper.db'))
        except Exception as e:
            if Configuration.verbose >= 2:
                Tools.print_error(e)

    def do_initial_check(self):

        with open(self.file_name, 'rb') as pe:
            f_data = bytearray(pe.read())

        f_data_incremental = f_data.copy()

        checker = self._get_std_checker()
        self.av_name = checker.get_avname()
        self.os_info = checker.get_osinfo()

        tags = Tools.pe_file_tags(f_data)
        sha256_hash = hashlib.sha256(f_data).hexdigest().lower()
        Logger.pl('{+} {C}SHA 256 Hash: {O}%s{W}' % sha256_hash)
        Logger.pl('{+} {C}Tags: {O}%s{W}' % tags)
        Logger.pl('{+} {C}AV Product: {O}%s{W}' % self.av_name)
        file_id = 0

        self.file_info = {
            'Name': self.file_name,
            'SHA 256 Hash': sha256_hash,
            'Tags': tags
        }

        db_file = self.db.select_first('src_file', sha256_hash=sha256_hash,
                                       finished='T')
        if db_file is not None and len(db_file) > 0:
            file_id = db_file['src_file_id']
        else:
            md5_hash = hashlib.md5(f_data).hexdigest().lower()
            file_id = self.db.insert_file(name=self.file_name, sha256_hash=sha256_hash, md5_hash=md5_hash,
                                          data=f_data, tags=tags)

        sql = "select count(distinct string_id) as qty from [string] where src_file_id = ?"
        db_data = self.db.select_raw(sql=sql, args=[file_id])
        if db_data is None or len(db_data) == 0:
            raise Exception('Cannot select quantity of tested files')

        if db_data[0]['qty'] > 0:
            return

        self.do_backup()

        verb = Configuration.verbose
        Configuration.verbose = 4

        Logger.pl('{*} {C}Starting initial checking...{W}')

        strippers = []

        try:
            from avsniper.formats.microsoft_pe import MicrosoftPe
            pe_file = MicrosoftPe.from_bytes(f_data)

            res_tree = Tools.pe_resource_table(
                data=pe_file,
                highlight_address=0,
                show_only_highlighted=False
            )
            if res_tree is not None and res_tree != "":
                res_tree = '  ' + '\n   '.join(res_tree.strip('\n').split('\n')) + '\n'
                Logger.pl('{+} {C}Resources:\n{GR}%s{W}\n' % res_tree)

            cert_tree = Tools.pe_certificate(
                data=pe_file,
                highlight_address=0,
                highlight_data=None,
                show_only_highlighted=False
            )
            if cert_tree is not None and cert_tree != "":
                cert_tree = '  ' + '\n   '.join(cert_tree.strip('\n').split('\n')) + '\n'
                Logger.pl('{+} {C}Certificates:\n{GR}%s{W}\n' % cert_tree)

        except Exception as e:
            Tools.print_error(e)

        last_file = None
        try:

            try:
                Logger.pl('\n{*} {C}Checking original file{W}')

                if checker.check_file(
                    test_id=1,
                    name='Original',
                    hash=hashlib.md5(f_data).hexdigest().lower(),
                    crashed=not self._check_file(f_data),
                    data=f_data,
                    wait_time=self.sleep,
                    force_execution=True,
                ):
                    self._print_and_exit('{!} {R}Fail: {O}The original file have not been flagged as malicious, '
                                         'so we cannot continue!{W}\n')

            except Exception as e:
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot check original file: {O}%s{W}' % str(e))
                if verb >= 3:
                    Tools.print_error(e)

            try:
                Logger.pl('\n{*} {C}Checking extra PE data{W}')
                peonly_data = Tools.pe_strip_extradata(f_data)
                if peonly_data is None:
                    raise Exception('Return is empty')

                strippers.append('Raw data after PE structure')
                last_file = peonly_data
                if checker.check_file(
                    test_id=1,
                    name='Raw data after PE structure',
                    hash=hashlib.md5(peonly_data).hexdigest().lower(),
                    crashed=not self._check_file(peonly_data),
                    data=peonly_data,
                    wait_time=self.sleep,
                    force_execution=True,
                ):
                    raise StripFoundException()

                Logger.pl('{*} {GR}Replacing original data with PE only{W}')

                f_data_incremental = peonly_data.copy()

            except StripFoundException as e:
                try:
                    # try to check if it is a PyInstaller to identify exactly position
                    pyinst = PyInstArchive(f_data)
                    l1 = True
                    toc_size = len(pyinst.tocList)

                    while l1 and len(pyinst.tocList) > 0:
                        tree = BinarySearchTree()
                        end = 0
                        for f in pyinst.tocList:
                            if f.cmprsdDataSize > 0:
                                tree.insert(f.position, f.cmprsdDataSize)
                                if (f.position + f.cmprsdDataSize) > end:
                                    end = f.position + f.cmprsdDataSize

                        tree.build()
                        l2 = True

                        # pop the first item (root node)
                        tree.get_next()

                        while l1 and l2 and (t := tree.get_next()) is not None:
                            m1 = t.get_min()
                            m2 = t.get_max()
                            if m1 is None or m2 is None:
                                raise StripFoundException()

                            data_bytes = f_data.copy()
                            addr = m1.address
                            size = (m2.address + m2.size) - addr
                            for i in range(0, size):
                                data_bytes[addr + i] = 0x00

                            # clean related metadata
                            for f in [
                                f1
                                for f1 in pyinst.tocList
                                if m1.address <= f1.position <= m2.address
                            ]:
                                addr = f.header_position
                                for i in range(0, f.header_size):
                                    data_bytes[addr + i] = 0x00

                            if checker.check_file(
                                    test_id=1,
                                    name='Overlay 0x' + (
                                            ''.join([f'{x:02x}' for x in struct.pack('>I', m1.address)])).zfill(8) +
                                         ' -- 0x' + (
                                            ''.join(
                                                [f'{x:02x}' for x in struct.pack('>I', m2.address + m2.size)])).zfill(8)
                                    ,
                                    hash=hashlib.md5(data_bytes).hexdigest().lower(),
                                    crashed=not self._check_file(data_bytes),
                                    data=data_bytes,
                                    wait_time=self.sleep,
                                    force_execution=True,
                            ):
                                l2 = False
                                f_list = [
                                    f1
                                    for f1 in pyinst.tocList
                                    if f1.position < m1.address or f1.position > m2.address
                                    #if m1.address <= f1.position <= m2.address
                                ]
                                if toc_size != len(pyinst.tocList) and len(f_list) == len(pyinst.tocList):
                                    l1 = False
                                else:
                                    for f in f_list:
                                        #print(f.name)
                                        try:
                                            pyinst.tocList.pop(pyinst.tocList.index(f))
                                        except ValueError:
                                            pass

                        if l2:
                            l1 = False

                    if len(pyinst.tocList) == 0:
                        raise StripFoundException()

                    for f in pyinst.tocList:
                        data_bytes = f_data.copy()
                        addr = f.position
                        for i in range(0, f.cmprsdDataSize):
                            data_bytes[addr + i] = 0x00

                        if checker.check_file(
                                test_id=1,
                                name=f'Overlay {f.name}',
                                hash=hashlib.md5(data_bytes).hexdigest().lower(),
                                crashed=not self._check_file(data_bytes),
                                data=data_bytes,
                                wait_time=self.sleep,
                                force_execution=True,
                        ):
                            strippers.append(f'Original - Overlay {f.name}')
                            raise StripFoundException()
                except StripFoundException as e1:
                    raise e1
                except Exception as e1:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip extra data: {O}%s{W}' % str(e1))
                    if verb >= 3:
                        Tools.print_error(e1)
            except Exception as e:
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot strip extra data: {O}%s{W}' % str(e))
                if verb >= 3:
                    Tools.print_error(e)

            try:
                Logger.pl('\n{*} {C}Checking debug section{W}')
                nodebug_data = Tools.pe_strip_debug(f_data)
                if nodebug_data is None:
                    raise Exception('Return is empty')

                strippers.append('Debug')
                last_file = nodebug_data
                if checker.check_file(
                    test_id=1,
                    name='Debug',
                    hash=hashlib.md5(nodebug_data).hexdigest().lower(),
                    crashed=not self._check_file(nodebug_data),
                    data=nodebug_data,
                    wait_time=self.sleep,
                    force_execution=True,
                ):
                    raise StripFoundException()

                Logger.pl('{*} {GR}Replacing original data with Debug stripped{W}')

                f_data_incremental = nodebug_data.copy()

            except StripFoundException as e:
                raise e
            except Exception as e:
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot strip debug: {O}%s{W}' % str(e))
                if verb >= 3:
                    Tools.print_error(e)

            try:
                try:
                    Logger.pl('\n{*} {C}Checking digital certificate{W}')
                    nocert_data = Tools.pe_strip_certificate(f_data)
                    if nocert_data is None:
                        raise Exception('Return is empty')

                    last_file = nocert_data
                    if checker.check_file(
                            test_id=1,
                            name='Digital Certificate',
                            hash=hashlib.md5(nocert_data).hexdigest().lower(),
                            crashed=not self._check_file(nocert_data),
                            data=nocert_data,
                            wait_time=self.sleep,
                            force_execution=True,
                    ):
                        strippers = ['Digital Certificate']
                        raise StripFoundException()

                except StripFoundException as e:
                    raise e
                except Exception as e:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip certificates: {O}%s{W}' % str(e))
                    if verb >= 3:
                        Tools.print_error(e)

                try:
                    Logger.pl('\n{*} {C}Checking digital certificate + Debug{W}')
                    nocert_data = Tools.pe_strip_certificate(f_data_incremental)
                    if nocert_data is None:
                        raise Exception('Return is empty')

                    strippers.append('Digital Certificate')
                    last_file = nocert_data
                    if checker.check_file(
                            test_id=1,
                            name='Digital Certificate',
                            hash=hashlib.md5(nocert_data).hexdigest().lower(),
                            crashed=not self._check_file(nocert_data),
                            data=nocert_data,
                            wait_time=self.sleep,
                            force_execution=True,
                    ):
                        raise StripFoundException()

                    Logger.pl('{*} {GR}Replacing original data with Digital Certificate stripped{W}')
                    f_data_incremental = nocert_data.copy()

                except StripFoundException as e:
                    raise e
                except Exception as e:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip certificates: {O}%s{W}' % str(e))
                    if verb >= 3:
                        Tools.print_error(e)

            except StripFoundException as e:

                Logger.pl('{*} {GR}Checking with Fake Certificate chain{W}')

                res_path = str(Path(os.path.join(Configuration.path, '../certificates')).resolve())
                if not os.path.isdir(res_path):
                    os.mkdir(res_path)

                rnd = StringPart.random_string(8, 'S').decode("UTF-8")
                p12_name = os.path.join(res_path, f'pkcs12_{rnd}.pfx')
                exe_name = os.path.join(Configuration.path, f'pkcs12_{rnd}.exe')

                with open(exe_name, 'wb') as p12:
                    p12.write(f_data_incremental)

                # Try to check with a Fake certificate chain
                Tools.pe_create_fake_cert_pkcs12(f_data, p12_name)

                status_code, stdout, stderr = Process.call(
                    command=("signtool.exe sign /td sha256 /fd sha256 /a "
                             "/tr http://timestamp.digicert.com /p 123456 "
                             f"/f \"{p12_name}\" "
                             f"\"{exe_name}\" "),
                    path_list=["C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\"],
                    cwd=Configuration.path
                )

                if status_code != 0:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot sign with the new certificates{W}')
                    if verb >= 3:
                        Logger.pl('{GR}%s{W}' % stderr)

                with open(exe_name, 'rb') as pe:
                    new_f_data = bytearray(pe.read())

                if not checker.check_file(
                        test_id=1,
                        name='Fake Digital Certificate',
                        hash=hashlib.md5(new_f_data).hexdigest().lower(),
                        crashed=not self._check_file(new_f_data),
                        data=new_f_data,
                        wait_time=self.sleep,
                        force_execution=True,
                ):
                    Logger.pl('{!} {R}AV Flagged PE with fake Digital Certificate{W}')
                else:
                    if not self.cert_only:
                        raise StripFoundException()

                if not self.cert_only:
                    raise e

            for k, res_check in dict({
                'Icon': [
                        MicrosoftPe.DirectoryEntryType.icon,
                        MicrosoftPe.DirectoryEntryType.group_cursor4,
                ],
                'Version Info': [
                    MicrosoftPe.DirectoryEntryType.version
                ],
                'Manifest': [
                    MicrosoftPe.DirectoryEntryType.manifest
                ],
                'All Resources': [
                    MicrosoftPe.DirectoryEntryType.icon,
                    MicrosoftPe.DirectoryEntryType.group_cursor4,
                    MicrosoftPe.DirectoryEntryType.version,
                    MicrosoftPe.DirectoryEntryType.manifest
                ]
            }).items():

                try:
                    Logger.pl('\n{*} {C}Checking %s{W}' % k)

                    # Using original file
                    nores_data = Tools.pe_strip_resources(f_data, res_check, error_on_equal=False)
                    if nores_data is None:
                        raise Exception('Return is empty')

                    last_file = nores_data
                    if checker.check_file(
                            test_id=1,
                            name=k,
                            hash=hashlib.md5(nores_data).hexdigest().lower(),
                            crashed=not self._check_file(nores_data),
                            data=nores_data,
                            wait_time=self.sleep,
                            force_execution=True,
                    ):
                        strippers = [k]
                        raise StripFoundException()

                    # Using incremental stripped file
                    strippers.append(k)
                    nores_data = Tools.pe_strip_resources(f_data_incremental, res_check, error_on_equal=False)
                    last_file = nores_data
                    if checker.check_file(
                            test_id=1,
                            name=k,
                            hash=hashlib.md5(nores_data).hexdigest().lower(),
                            crashed=not self._check_file(nores_data),
                            data=nores_data,
                            wait_time=self.sleep,
                            force_execution=True,
                    ):
                        raise StripFoundException()

                    f_data_incremental = nores_data.copy()

                except StripFoundException as e:
                    raise e
                except Exception as e:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip %s: {O}%s{W}' % (k, str(e)))
                    if verb >= 3:
                        Tools.print_error(e)

            if self.no_strip:
                f_data_incremental = f_data.copy()

            if not self.no_strip:
                Logger.pl('{*} {GR}Replacing original file data with stripped to next tests...{W}')

                self.db.update('src_file', filter_data=dict(src_file_id=file_id),
                               data=StringPart.b64encode(f_data_incremental),
                               md5_hash=hashlib.md5(f_data_incremental).hexdigest().lower(),
                               finished="F"
                               )

            self.do_backup()

        except StripFoundException as ste:
            self.do_backup()
            if not self.no_strip:
                self._print_and_exit('{!} {R}WARNING! {O}The initial file checkers have not been flagged '
                                     'as malicious!\n     {C}Data stripped: \n      {O}*{GR} %s{W}\n' %
                                     '\n      {O}*{GR} '.join(strippers), data=last_file)

        Configuration.verbose = verb

    def do_step1(self):
        parser = self._get_args()
        enum = EnumerateFile()
        enum.add_commands(parser)
        enum.add_flags(parser)

        a_args = [
            "--file", self.file_name,
            "--min-size", str(self.min_size),
            "--threshold", str(self.threshold),
        ]
        if self.no_dotnet:
            a_args.append("--no-dotnet")
        if self.use_raw:
            a_args.append("--raw")
        if self.disable_crashable_string_check:
            a_args.append("--disable-crashable-string-check")
        if self.cert_only:
            a_args.append("--cert-only")
        args = parser.parse_args(a_args)
        enum.load_from_arguments(args=args)

        enum.run()
        pass

    def do_step2(self):
        self.do_backup()
        qty = 0
        sql = ("select count(distinct string_id) as qty from [string] "
               "where string_id in ("
               "    select t.string_id from [test_file] as t where t.finished = 'T' and t.type in ('I', 'U', 'S') "
               ")")
        db_data = self.db.select_raw(sql=sql, args=[])
        if db_data is None or len(db_data) == 0:
            raise Exception('Cannot select quantity of tested files')

        qty = db_data[0]['qty']

        if not self.do_strip([
            "--disable-incremental",
            "--disable-sliced",
            "--linear",
            "--strategy", "rev"
        ]):
            raise Exception('Ops! Fail running first check strip!')

        shutil.copy(Configuration.db_name, self.bkp2)

        last_count = -1
        for rnd in range(1, self.st1_rounds + 1):

            try:
                shutil.copy(Configuration.db_name, self.bkp1)

                if not self.do_strip([
                    "--disable-unique",
                    "--disable-sliced",
                    "--linear",
                    "--strategy", "rev"
                ]):
                    raise Exception('Step2 - fail running strip at round %s' % rnd)

                if not self.do_check_remote([
                    "--api", str(self.api_url),
                    "--execute",
                    "-T", str(self.tasks),
                    "-sleep", str(int(self.sleep)),
                    "--continue",
                ] + (["--command", str(self.cmd)] if self.cmd is not None else [])):
                    raise Exception('fail running remote check at round %s' % rnd)

                if Configuration.exit_code == 99999:
                    Logger.pl('{!} {R}Fail: {O}Error found at round %s, rollbacking database file...!{W}' % rnd)
                    shutil.copy(self.bkp2, Configuration.db_name)
                    return

                cnt = self.get_flagged_count(['I', 'U', 'S'])
                if cnt == last_count:
                    self.do_bl_to_str()
                    return

                last_count = cnt
                shutil.copy(self.bkp1, self.bkp2)
                self.do_bl_to_str()

            except Exception as e:
                raise e

    def do_step3(self):
        self.do_backup()
        rnd = 0
        while True:
            rnd += 1

            try:
                if not self.do_strip([
                    "--disable-incremental",
                    "--disable-sliced",
                    "--linear",
                    "--strategy", "rev"
                ]):
                    raise Exception('Step 3 - fail running strip at round %s' % rnd)

                if not self.do_check_remote([
                                                "--api", str(self.api_url),
                                                "--execute",
                                                "-T", str(self.tasks),
                                                "-sleep", str(int(self.sleep)),
                                            ] + (["--command", str(self.cmd)] if self.cmd is not None else [])):
                    raise Exception('fail running remote check at round %s' % rnd)

                if Configuration.exit_code == 99999:
                    return

                cnt = self.get_flagged_count(['I', 'U', 'S'])
                if cnt == 0:
                    return

            except Exception as e:
                raise e

    def do_step4(self):
        cnt = self.get_flagged_count(['I', 'U', 'S'])

        if cnt == 0 or self.db.select_raw(sql="select count(*) as count from black_list", args=[])[0]['count'] == 0:
            return

        self.do_backup()
        shutil.copy(Configuration.db_name, self.bkp1)

        try:
            self.do_bl_to_str()

            if not self.do_strip([
                "--disable-incremental",
                "--disable-sliced",
                "--linear",
                "--strategy", "rev"
            ]):
                shutil.copy(self.bkp1, Configuration.db_name)
                Logger.pl('{!} {R}Ops! Fail running strip, rollbacking database file...{W}')

            if not self.do_check_remote([
                                            "--api", str(self.api_url),
                                            "--execute",
                                            "-T", str(self.tasks),
                                            "-sleep", str(int(self.sleep)),
                                            "--continue",
                                            "--initial-check"
                                        ] + (["--command", str(self.cmd)] if self.cmd is not None else [])):
                shutil.copy(self.bkp1, Configuration.db_name)
                Logger.pl('{!} {R}Ops! Fail running remote check, rollbacking database file...{W}')

            if Configuration.exit_code == 99999:
                Logger.pl('{!} {R}Ops!, rollbacking database file...')
                shutil.copy(self.bkp1, Configuration.db_name)
                return

            try:
                self.do_step3()
            except Exception as e1:
                if Configuration.verbose >= 3:
                    Logger.pl('{!} {R}Error: {O}%s{W}' % str(e1))
                shutil.copy(self.bkp1, Configuration.db_name)

        except Exception as e:
            raise e

    def do_step5(self):
        cnt = self.get_flagged_count(['I', 'U', 'S'])

        if cnt > 0 or self.db.select_raw(sql="select count(*) as count from black_list", args=[])[0]['count'] > 0:
            return

        self.do_backup()

        Logger.pl('{!} {R}WARNING: {O}Zero files flagged and Black List is empty!{W}')
        Logger.pl('{?} {GR}Trying direct strategy!{W}')

        rnd = 0
        #total = self.db.select_raw(sql="select count(*) as count from [string]", args=[])[0]['count']
        while True:
            rnd += 1
            try:
                if not self.do_strip([
                    "--disable-unique",
                    "--disable-sliced",
                    "--linear",
                    "--strategy", "direct"
                ]):
                    raise Exception('Step 5 - fail running strip at round %s' % rnd)

                if not self.do_check_remote([
                                                "--api", str(self.api_url),
                                                "--execute",
                                                "-T", str(self.tasks),
                                                "-sleep", str(int(self.sleep)),
                                            ] + (["--command", str(self.cmd)] if self.cmd is not None else [])):
                    raise Exception('Step 5 - fail running remote check at round %s' % rnd)

                if Configuration.exit_code == 99999:
                    return

                cnt = self.get_flagged_count(['I', 'U', 'S'])
                if cnt == 0:
                    return

            except Exception as e:
                # Rollback database
                Logger.pl('\n{!} {R}Rollbacking database file...{W}')
                shutil.copy(self.bkp1, Configuration.db_name)
                raise e

    def do_step6(self):
        cnt = self.get_flagged_count(['I', 'U', 'S'])

        if cnt > 0 or self.db.select_raw(sql="select count(*) as count from black_list", args=[])[0]['count'] > 0:
            return

        self.do_backup()
        shutil.copy(Configuration.db_name, self.bkp1)

        self.do_bl_to_str()

        rnd = 0
        while True:

            self.do_bl_to_str()

            internal = True
            while internal:
                rnd += 1

                self.do_bl_to_str()

                try:
                    if not self.do_strip([
                        "--disable-incremental",
                        "--disable-sliced",
                        "--linear",
                        "--strategy", "direct"
                    ]):
                        raise Exception('Step 5 - fail running strip at round %s' % rnd)

                    if not self.do_check_remote([
                                                    "--api", str(self.api_url),
                                                    "--execute",
                                                    "-T", str(self.tasks),
                                                    "-sleep", str(int(self.sleep)),
                                                ] + (["--command", str(self.cmd)] if self.cmd is not None else [])):
                        raise Exception('Step 5 - fail running remote check at round %s' % rnd)

                    if Configuration.exit_code == 99999:
                        Logger.pl('{!} {R}Ops!, rollbacking database file...')
                        shutil.copy(self.bkp1, Configuration.db_name)
                        return

                    cnt = self.get_flagged_count(['I', 'U', 'S'])
                    internal = not cnt == 0

                except Exception as e:
                    # Rollback database
                    Logger.pl('\n{!} {R}Rollbacking database file...{W}')
                    shutil.copy(self.bkp1, Configuration.db_name)
                    raise e

    def do_step7(self):

        cnt = self.get_flagged_count(['I', 'U', 'S'])

        if cnt > 0 or self.db.select_raw(sql="select count(*) as count from black_list", args=[])[0]['count'] > 0:
            return

        self.do_backup()

        Logger.pl('{!} {R}WARNING: {O}Zero files flagged and Black List is empty!{W}')
        Logger.pl('{?} {GR}Trying some permutations!{W}')

        shutil.copy(Configuration.db_name, self.bkp1)
        shutil.copy(Configuration.db_name, self.bkp2)

        # Zeroing temp db (is is used to copy and replicate several tests)
        tmp = SniperDB(db_name=self.bkp2)
        tmp.execute(sql="delete from [black_list]", args=[])
        tmp.execute(sql="delete from [test_file]", args=[])

        # Original DB
        tempdb = SniperDB(db_name=self.bkp1)

        try:

            Logger.pl('{+} {C}Generating permutations{W}')

            sql = "select sf.src_file_id, sf.sha256_hash, sf.data as src_file_data from [src_file] sf "
            self.files = {
                r['src_file_id']: dict(
                    sha256_hash=r['src_file_id'],
                    data=Tools.pe_strip_certificate(StringPart.b64decode(r['src_file_data']), error_on_equal=False)
                )
                for r in tempdb.select_raw(sql=sql, args=[])
            }

            a_strings = [
                str(r['string_id'])
                for r in tempdb.select_raw(
                    sql="select string_id, encoding, encoded_string from [string] order by address", args=[])
                if (s := StringPart.b64decode_as_str(r['encoded_string'], r['encoding'])) is not None
                and self.is_permitted(s)
            ]

            sql = ("select s.src_file_id, s.string_id, s.address, s.bytes_size, s.encoding "
                   "from [string] as s "
                   "order by s.address asc ")
            strings_db_data = self.db.select_raw(sql=sql, args=[])

            if strings_db_data is None or len(strings_db_data) == 0:
                return

            perm = [p for p in permutations(a_strings, 2)]
            Logger.pl('{+} {C}Permutations of size 2: {O}%s possibilities{W}' % len(perm))

            s_wait = int(len(perm) * 0.1)
            if s_wait < self.tasks:
                s_wait = self.tasks

            e_tasks = self.tasks
            if len(perm) < 30:
                e_tasks = 1
            elif len(perm) < 60:
                e_tasks = 2

            shutil.copy(self.bkp2, Configuration.db_name)

            Logger.pl('{+} {C}Running with {O}%s{C} threads{W}' % e_tasks)

            with Worker(callback=self.permutation_callback, per_thread_callback=self.thread_start_callback,
                        threads=e_tasks) as t:
                t.start()

                with progress.Bar(label=" \033[0m\033[36mChecking permutations ",
                                  expected_size=len(perm),
                                  show_percent=True,
                                  no_tty_every_percent=10,
                                  auto_hide_cursor=True) as bar:

                    t1 = threading.Thread(target=self.status,
                                          kwargs=dict(sync=t, bar=bar))
                    t1.daemon = True
                    t1.start()

                    try:
                        Cursor.hide()
                        for rl, row in enumerate(perm):
                            if not t.running:
                                break

                            t.add_item([
                                r
                                for r in strings_db_data
                                if str(r['string_id']) in row
                            ])

                            while t.count > s_wait and t.running:
                                time.sleep(0.3)

                        t.wait_finish()

                    except KeyboardInterrupt as e:
                        bar.hide = True
                        time.sleep(0.4)
                        bar.clear_line()

                        raise e
                    finally:
                        t.close()
                        t1.join()
                        bar.hide = True
                        bar.no_tty_every_percent = None
                        Tools.clear_line()
                        Cursor.show()

            if self.enumeration_found is not None:
                shutil.copy(self.bkp2, Configuration.db_name)
                tmp = SniperDB(db_name=Configuration.db_name)
                tmp.execute(sql="delete from [string] where string_id not in (%s)" %
                                ', '.join(['?' for _ in self.enumeration_found]),
                            args=[s['string_id'] for s in self.enumeration_found])

                try:
                    self.do_step3()
                except Exception as e1:
                    if Configuration.verbose >= 3:
                        Logger.pl('{!} {R}Error: {O}%s{W}' % str(e1))
                    shutil.copy(self.bkp1, Configuration.db_name)
                    return

                cnt = self.get_flagged_count(['I', 'U', 'S'])
                if cnt > 0 or self.db.select_raw(
                        sql="select count(*) as count from black_list", args=[])[0]['count'] > 0:
                    # Found a valid permutation, just return with this DB
                    return
                else:
                    shutil.copy(self.bkp1, Configuration.db_name)
            else:
                shutil.copy(self.bkp1, Configuration.db_name)

        except KeyboardInterrupt as e:
            # Rollback database
            Logger.pl('\n{!} {R}Rollbacking database file...{W}')
            shutil.copy(self.bkp1, Configuration.db_name)
            raise e
        except Exception as e:
            # Rollback database
            Logger.pl('\n{!} {R}Rollbacking database file...{W}')
            shutil.copy(self.bkp1, Configuration.db_name)
            raise e

    def status(self, sync, bar):
        try:
            last_data = 0
            while sync.running:
                if self.count != last_data:
                    bar.show(self.count)
                    last_data = self.count
                time.sleep(0.3)
        except KeyboardInterrupt as e:
            raise e
        except:
            pass
        finally:
            Tools.clear_line()

    def thread_start_callback(self, index, **kwargs):
        time.sleep(0.5 * float(index))

        return self._get_std_checker()

    def permutation_callback(self, worker, entry, thread_callback_data, thread_count, **kwargs):

        checker = thread_callback_data

        try:
            if entry is None:
                return

            if not isinstance(entry, list):
                return

            if len(entry) == 0:
                return

            st_data = self.files[entry[0]['src_file_id']]['data'].copy()
            addr = 0
            for row in entry:
                addr = row['address']
                bytes_size = row['bytes_size']

                # Fill with ransom string with same size
                rnd = StringPart.random_string(raw_size=bytes_size, encoding=row['encoding'])
                for i in range(0, bytes_size):
                    st_data[addr + i] = rnd[i]

            if checker.check_file(
                test_id=addr,
                name=None,
                hash=hashlib.md5(st_data).hexdigest().lower(),
                crashed=True,
                data=st_data,
                wait_time=self.sleep,
                force_execution=True,
            ):
                if self.enumeration_found is not None:
                    self.enumeration_found = entry
                    worker.close()

        except KeyboardInterrupt as e:
            worker.close()
        except Exception as e:
            Tools.print_error(e)
        finally:
            self.count += 1

    @classmethod
    def is_permitted(cls, string: str) -> bool:
        if string.find('set_') >= 0:
            return False
        elif string.find('get_') >= 0:
            return False
        elif '.xaml' in string:
            return False
        elif re.match(r'[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\Z', string.replace("{", "").replace("}", ""), re.I):
            return False

        try:
            UUID(string.replace("{", "").replace("}", ""), version=4)
            return False
        except ValueError:
            pass

        return True

    def do_strip(self, a_args: list[str]) -> bool:
        Tools.kill_all_running()

        parser = self._get_args()
        strip = StripFile()
        strip.add_commands(parser)
        strip.add_flags(parser)

        args = parser.parse_args(a_args)
        strip.load_from_arguments(args=args)

        strip.run()

        return True

    def do_check_remote(self, a_args: list[str]) -> bool:
        Tools.kill_all_running()
        Configuration.exit_code = 0

        parser = self._get_args()
        checker = RemoteFile()
        checker.add_commands(parser)
        checker.add_flags(parser)

        args = parser.parse_args(a_args)
        checker.load_from_arguments(args=args)

        checker.run()

        return True

    def do_bl_to_str(self) -> bool:
        Tools.kill_all_running()

        parser = self._get_args()
        transform = TransforBlackListToStrings()
        transform.add_commands(parser)
        transform.add_flags(parser)

        args = parser.parse_args([])
        transform.load_from_arguments(args=args)

        transform.run()

        return True

    def do_get_list(self) -> bool:
        Tools.kill_all_running()

        parser = self._get_args()
        get_list = ListStrings()
        get_list.add_commands(parser)
        get_list.add_flags(parser)

        args = parser.parse_args(["--black-list"])
        get_list.load_from_arguments(args=args)

        get_list.run()

        return True

    def get_flagged_count(self, types: list[str]) -> int:
        sql = ("select "
               "    sum(case "
               "        when tf.flagged == 'T' and tf.strategy == 1 then 1 "
               "        when tf.flagged == 'F' and tf.strategy == 2 then 1 "
               "        else 0 end) as flagged, "
               "    sum(case "
               "        when tf.flagged == 'F' and tf.strategy == 1 then 1 "
               "        when tf.flagged == 'T' and tf.strategy == 2 then 1 "
               "        else 0 end) as clean, "
               "    tf.type "
               "from test_file tf "
               "where tf.finished == 'T' "
               "group by tf.type order by 1 desc")

        return sum([
            int(r['flagged'])
            for r in self.db.select_raw(sql=sql, args=[])
            if len(types) == 0 or r['type'] in types
        ])

    @classmethod
    def _get_args(cls):
        return argparse.ArgumentParser(usage=argparse.SUPPRESS)

    def _get_std_checker(self):
        parser = self._get_args()
        checker = RemoteFile()
        checker.add_commands(parser)
        checker.add_flags(parser)
        checker.quiet = True

        args = parser.parse_args([
                                     "--api", str(self.api_url),
                                     "--execute",
                                     "-T", "1",
                                     "-sleep", str(int(self.sleep)),
                                     "--initial-check"
                                 ] + (["--command", str(self.cmd)] if self.cmd is not None else []))
        checker.load_from_arguments(args=args)

        return checker

    def _check_file(self, data: Union[bytes, bytearray]) -> bool:

        rnd = StringPart.random_string(8, 'S').decode("UTF-8")
        filename = os.path.join(Configuration.path, f'tst_{rnd}.exe')
        try:
            with(open(filename, 'wb')) as f:
                f.write(data)

            return ExeRunner.execute(filename)
        except:
            return False
        finally:
            try:
                os.unlink(filename)
            except:
                pass

    def _print_and_exit(self, message: str, exit_code: int = 0, data: Union[bytes, bytearray, None] = None):
        Logger.pl('\n{+} {C}AV Product: {O}%s{W}' % self.av_name)
        Logger.pl('{+} {C}OS: {O}%s{W}' % self.os_info)
        if self.file_info is not None and isinstance(self.file_info, dict):
            Logger.pl('{+} {C}EXE information:\n     {O}*{GR} %s{W}\n' %
                      '\n     {O}*{GR} '.join([
                         '%s: \033[92m%s{GR}' % (k, v)
                         for k, v in self.file_info.items()
                      ]))

        if data is not None and len(data) > 0:
            rnd = StringPart.random_string(8, 'S').decode("UTF-8")
            tmp_name = Tools.calc_pe_path_name(data).replace('\\', '/').strip('/').split('/', 2)[0]
            filename = os.path.join(Configuration.path, f'0000_{tmp_name}_{rnd}.exe')

            with(open(filename, 'wb')) as f:
                f.write(data)

            Logger.pl('{+} {GR}Sample file saved at: {O}%s{W}\n\n' % filename)

        Logger.pl(message)

        Configuration.exit_code = exit_code
        exit(exit_code)
