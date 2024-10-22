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
from urllib.parse import urlparse
from uuid import UUID

import requests
import yaml

import hexdump
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

requests.packages.urllib3.disable_warnings()


class ResultFoundException(Exception):
    pass


class MultiAv(CmdBase):
    check_database = False
    db = None
    file_name = None
    config_file = None
    servers = []
    f_data = None
    t_line = None
    t_header_prefix = None
    result_table = {}
    sleep = 5
    repeat = 1

    def __init__(self):
        super().__init__('multi-av', 'Check original file at multiple AVs')

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
                           default='./multiav_config.yml',
                           dest=f'config_file',
                           help=Color.s('Configuration file. (default: {G}./config.yml{W})'))

        flags.add_argument('--create-config',
                           action='store_true',
                           default=False,
                           dest=f'create_config',
                           help=Color.s('Create config sample'))

        flags.add_argument('--repeat',
                           action='store',
                           metavar='[number]',
                           type=int,
                           default=1,
                           dest=f'repeat',
                           help=Color.s('Number of time to repeat the test'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        regex = re.compile(
            r'^(?:http|ftp|socks|socks5)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

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

        '''
                    'servers': [
                {
                    'name': 'AV Product Name - Sample 001',
                    'av_config': {
                        'api_url': 'http://ip_or_host:8080/',
                        'remote_command': '',
                        'get_remote_av_name': True
                    }
                },
        '''

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
                if data is not None and data.get('servers', None) is not None:
                    servers = data.get('servers', {})
                    if isinstance(servers, list):
                        self.servers = []
                        for srv in servers:
                            if isinstance(srv, dict) and 'name' in srv.keys() and 'av_config' in srv.keys():
                                if isinstance(srv['av_config'], dict) and 'api_url' in srv['av_config'].keys():
                                    name = srv.get('name', None)
                                    cmd = srv['av_config'].get('remote_command', '')
                                    get_remote_av_name = srv['av_config'].get('get_remote_av_name', True)
                                    api_url = srv['av_config'].get('api_url', '')
                                    try:
                                        if re.match(regex, api_url) is None:
                                            raise Exception("Invalid")

                                        av1 = urlparse(api_url)
                                        self.servers.append(dict(
                                            name=name,
                                            cmd=cmd,
                                            get_remote_av_name=get_remote_av_name,
                                            api_url=f"{av1.scheme}://{av1.netloc}"
                                        ))
                                    except:
                                        Logger.pl(
                                            '{!} {R}Error: Invalid API URL "{O}%s{R}".{W}\n' %
                                            api_url
                                        )
                                        exit(1)

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

        if len(self.servers) == 0:
            Logger.pl(
                '{!} {R}Error: The server list is empty.\n'
            )
            exit(1)

        if not os.path.exists(args.pe_file):
            Logger.pl(
                '{!} {R}error: PE file "{O}%s{R}" does not exists{W}\r\n' % args.pe_file)
            exit(1)

        try:
            with open(args.pe_file, 'r') as f:
                self.file_name = args.pe_file
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

        self.t_line = ' ' + ''.join([
            '%s──' % c for k, c in sorted(Color.gray_scale.items(), key=lambda x: x[0], reverse=True)
        ]) + Color.s('{W}\n')

        self.t_header_prefix = ' \033[38;5;52m=\033[38;5;88m=\033[38;5;124m=\033[38;5;160m=\033[38;5;196m> '

        self.repeat = args.repeat

        #Configuration.db_name = "./temp.db"

        #if not os.path.isfile(Configuration.db_name):
        #    SniperDB(auto_create=True, db_name=Configuration.db_name)

        #self.db = self.open_db(args)

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
            'servers': [
                {
                    'name': 'AV Product Name - Sample 001',
                    'av_config': {
                        'api_url': 'http://ip_or_host:8080/',
                        'remote_command': '',
                        'get_remote_av_name': True
                    }
                },
                {
                    'name': 'AV Product Name - Sample 002',
                    'av_config': {
                        'api_url': 'http://ip_or_host:8080/',
                        'remote_command': 'powershell -ep bypass -file E:\T3scan\scan.ps1 -Filename {exe}',
                        'get_remote_av_name': False
                    }
                },
            ]
        }

        return sample_config

    def run(self):

        for srv_data in self.servers:
            srv = srv_data['api_url']

            Logger.pl('{+} {C}Checking connection with {O}%s{W}' % srv)

            try:
                r1 = requests.get(f"{srv}/api/v1/ping/",
                                  verify=False,
                                  timeout=10,
                                  headers={
                                      'content-type': 'application/json'
                                  })

                if r1.status_code != 200:
                    Logger.pl('{!} {R}Fail: {O}Cannot connect to the web server!{W}')
                    return
            except Exception as e:
                Logger.pl('{!} {R}Fail: {O}Cannot connect to the web server:{W}')
                Tools.print_error(e)
                return

        with open(self.file_name, 'rb') as pe:
            self.f_data = bytearray(pe.read())

        try:
            tags = Tools.pe_file_tags(self.f_data)
            sha256_hash = hashlib.sha256(self.f_data).hexdigest().lower()

            git = self.get_git_log()

            Logger.pl('{+} {C}SHA 256 Hash: {O}%s{W}' % sha256_hash)
            Logger.pl('{+} {C}Tags: {O}%s{W}' % tags)
            if git != '':
                Logger.pl('{+} {C}Git info: {O}%s{W}' % git)

            certs = [cert for cert in Tools.pe_certificate_list(self.f_data)]

            for t in range(self.repeat):
                if self.repeat > 1:
                    Logger.pl('{+} {GR}Test loop {O}%s{W}' % (t + 1))

                for srv in self.servers:
                    self.check_av(**srv)

                if t > 2 and (t + 1) % 10 == 0:
                    Logger.pl('\n{+} Temp status{W}')
                    t_status = self.get_table()
                    t_status += '\n\n'
                    Logger.pl(t_status)

            timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S GMT')
            name = Path(self.file_name).name
            info = {
                **{
                    'File': name,
                    'Test date': timestamp,
                    'SHA 256 Hash': sha256_hash,
                    'Tags': tags,
                },
                **{
                    'Git Info': git if git != '' else 'Empty'
                },
                **({
                       'X509 Certificates': 'Empty'
                   } if len(certs) == 0 else {})
            }

            tmp = '\n'.join([
                Color.s("  {O}%s: {G}%s{W}" % (k, v)) for k, v in info.items()
            ]) + '\n'

            table = self.t_line
            table += tmp
            # table += self.t_line

            if len(certs) > 0:
                color1 = "{O}"
                color2 = "\033[92m"
                color3 = "{C}"
                color4 = "\033[35m"
                color5 = "{GR}"

                table += f'  {color1}X509 Certificates{color5}, entries: {len(certs)}\n'
                table += f'{color5}\n'.join([
                    f'{color5}\n'.join([
                                           f"   {m} {color2}X509 Entry {idx}",
                                           f"   {m2}   ├── Subject.....: {color3}{cert['subject']}",
                                           f"   {m2}   ├── Serial......: {color1}{cert['serial_number']}",
                                           f"   {m2}   ├── Issuer......: {color1}{cert['issuer']}",
                                           f"   {m2}   ├── Fingerprint.: {color1}{cert['fingerprint']}",
                                           f"   {m2}   └── {color4}Alternate names{color5}, entries {sc}"
                                       ] + [
                                           f"   {m2}        {m3} {color4}Alternate name {idx2}{color5}: {an}"
                                           for idx2, an in enumerate(cert['san'])
                                           if (m3 := '├──' if idx == sc - 1 else '└──') is not None
                                       ])
                    for idx, cert in enumerate(Tools.pe_certificate_list(self.f_data))
                    if (f1 := (idx == len(certs) - 1)) is not None and
                       (m := '└──' if f1 else '├──') is not None and
                       (m2 := '   ' if f1 else '│  ') is not None and
                       (sc := len(cert['san'])) is not None
                ])
                table += "\n\n"

            table += self.get_table()
            table += '\n\n'

            Logger.pl('\n{+} Test result{W}')
            Logger.pl(table)

        except KeyboardInterrupt as e:
            raise e

    def get_table(self) -> str:

        db_data = [
            {
                **{
                    'AV Name': res['av_name'] if i == 0 else "",
                    'Timestamp (GMT)': res['timestamp'].strftime("%H:%M:%S") if i == 0 else "",
                    'Remote OS': res['os_info'] if i == 0 else "",
                    'Host': res['url'] if i == 0 else "",
                    'Test Result': res['result'] if i == 0 else "",
                    'Item': Color.s(k),
                    'Status': Color.s(v)
                }
            }
            for _, res in sorted(
                self.result_table.items(),
                key=lambda x: x[1]['av_name'].lower() + x[1]['timestamp'].strftime("%Y-%m-%d-%H:%M:%S"),
                reverse=False)
            for i, (k, v) in enumerate(res['tests'].items())
        ]

        tmp = Tools.get_ansi_tabulated(db_data, " ")
        for o, n in {
            'Clean': '{G}clean',
            'Flagged': '{R}flagged',
            'Success': '{O}success'
        }.items():
            tmp = tmp.replace(o, Color.s(n)).replace(o.lower(), Color.s(n))

        return Color.s(tmp)

    def get_git_log(self) -> str:
        retcode, stdout, stderr = Process.call(
            command="git log --decorate=full",
            cwd=str(Path(self.file_name).parent.resolve())
        )
        if retcode != 0:
            return ''

        txt = (stdout + '\n' + stderr).replace('\r', '\n').strip(' \n')
        return txt.split('\n')[0].strip()

    def check_av(self, name: str, api_url: str, cmd: str = None, get_remote_av_name: bool = True):

        cmd = cmd.strip(' ').strip('\t').strip('\r').strip(' ') if cmd is not None else None
        if cmd == "":
            cmd = None

        f_data = self.f_data.copy()
        f_data_incremental = self.f_data.copy()
        checker = self._get_std_checker(api_url, cmd=cmd)
        rnd = StringPart.random_string(8, 'S').decode("UTF-8")
        key = hashlib.md5(f"{api_url}_{rnd}".encode("UTF-8")).hexdigest().lower()

        av_name = checker.get_avname() if get_remote_av_name else name
        os_info = checker.get_osinfo()

        if key not in self.result_table.keys():
            self.result_table[key] = {
                'av_name': av_name,
                'os_info': os_info,
                'url': api_url,
                'result': 'undefined',
                'timestamp': datetime.datetime.utcnow(),
                'tests': {}
            }

        last_file = None
        try:

            try:
                Logger.pl('\n{*} {C}Checking original file at %s{W}' % av_name)

                st1 = checker.check_file(
                        test_id=1,
                        name='Original',
                        hash=hashlib.md5(f_data).hexdigest().lower(),
                        crashed=not self._check_file(f_data),
                        data=f_data,
                        wait_time=self.sleep,
                        force_execution=True,
                )

                self.result_table[key]['tests']['Original'] = 'clean' if st1 else 'flagged'

                if st1:
                    raise ResultFoundException()

            except ResultFoundException as e:
                raise e
            except Exception as e:
                self.result_table[key]['tests']['Original'] = 'error'

                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot check original file: {O}%s{W}' % str(e))
                if Configuration.verbose >= 3:
                    Tools.print_error(e)

            try:
                Logger.pl('\n{*} {C}Checking debug section at %s{W}' % av_name)
                peonly_data = Tools.pe_strip_extradata(f_data, error_on_equal=False)
                if peonly_data is None or self._is_equal(f_data, peonly_data):
                    self.result_table[key]['tests']['Raw data after PE structure'] = '{C}not present'
                else:

                    last_file = peonly_data
                    st2 = checker.check_file(
                            test_id=1,
                            name='Raw data after PE structure',
                            hash=hashlib.md5(peonly_data).hexdigest().lower(),
                            crashed=not self._check_file(peonly_data),
                            data=peonly_data,
                            wait_time=self.sleep,
                            force_execution=True,
                    )

                    self.result_table[key]['tests']['Original - Raw data after PE structure'] = 'Clean' if st2 else 'Flagged'

                    if st2:
                        raise ResultFoundException()

                    Logger.pl('{*} {GR}Replacing original data with PE only{W}')

                    f_data_incremental = peonly_data.copy()

            except ResultFoundException as e:
                raise e
            except Exception as e:
                self.result_table[key]['tests']['Raw data after PE structure'] = 'error'
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot strip extra data: {O}%s{W}' % str(e))
                if Configuration.verbose >= 3:
                    Tools.print_error(e)

            try:
                Logger.pl('\n{*} {C}Checking debug section at %s{W}' % av_name)
                nodebug_data = Tools.pe_strip_debug(f_data, error_on_equal=False)
                if nodebug_data is None or self._is_equal(f_data, nodebug_data):
                    self.result_table[key]['tests']['Debug section'] = '{C}not present'
                else:

                    last_file = nodebug_data
                    st2 = checker.check_file(
                            test_id=1,
                            name='Debug',
                            hash=hashlib.md5(nodebug_data).hexdigest().lower(),
                            crashed=not self._check_file(nodebug_data),
                            data=nodebug_data,
                            wait_time=self.sleep,
                            force_execution=True,
                    )

                    self.result_table[key]['tests']['Original - Debug data'] = 'Clean' if st2 else 'Flagged'

                    if st2:
                        raise ResultFoundException()

                    Logger.pl('{*} {GR}Replacing original data with Debug stripped{W}')

                    f_data_incremental = nodebug_data.copy()

            except ResultFoundException as e:
                raise e
            except Exception as e:
                self.result_table[key]['tests']['Debug section'] = 'error'
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot strip debug: {O}%s{W}' % str(e))
                if Configuration.verbose >= 3:
                    Tools.print_error(e)

            try:
                try:
                    Logger.pl('\n{*} {C}Checking digital certificate at %s{W}' % av_name)
                    nocert_data = Tools.pe_strip_certificate(f_data, error_on_equal=False)
                    if nocert_data is None or self._is_equal(f_data, nocert_data):
                        self.result_table[key]['tests']['Certificate'] = '{C}not present'
                    else:
                        last_file = nocert_data
                        st3 = checker.check_file(
                                test_id=1,
                                name='Digital Certificate',
                                hash=hashlib.md5(nocert_data).hexdigest().lower(),
                                crashed=not self._check_file(nocert_data),
                                data=nocert_data,
                                wait_time=self.sleep,
                                force_execution=True,
                        )

                        self.result_table[key]['tests']['Original - Certificate data'] = 'clean' if st3 else 'flagged'

                        if st3:
                            raise ResultFoundException()

                except ResultFoundException as e:
                    raise e
                except Exception as e:
                    self.result_table[key]['tests']['Certificate'] = 'error'
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip certificates: {O}%s{W}' % str(e))
                    if Configuration.verbose >= 3:
                        Tools.print_error(e)

                try:
                    Logger.pl('\n{*} {C}Checking digital certificate + Debug at %s{W}' % av_name)
                    nocert_data = Tools.pe_strip_certificate(f_data_incremental, error_on_equal=False)
                    if nocert_data is None or self._is_equal(f_data_incremental, nocert_data):
                        self.result_table[key]['tests']['Certificate and Debug'] = '{C}not present'
                    else:

                        last_file = nocert_data
                        st4 = checker.check_file(
                                test_id=1,
                                name='Digital Certificate',
                                hash=hashlib.md5(nocert_data).hexdigest().lower(),
                                crashed=not self._check_file(nocert_data),
                                data=nocert_data,
                                wait_time=self.sleep,
                                force_execution=True,
                        )

                        self.result_table[key]['tests']['Original - Certificate and Debug'] = 'clean' if st4 else 'flagged'

                        if st4:
                            raise ResultFoundException()

                        Logger.pl('{*} {GR}Replacing original data with Digital Certificate stripped{W}')

                        f_data_incremental = nocert_data.copy()

                except ResultFoundException as e:
                    raise e
                except Exception as e:
                    self.result_table[key]['tests']['Certificate and Debug'] = 'error'
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip certificates: {O}%s{W}' % str(e))
                    if Configuration.verbose >= 3:
                        Tools.print_error(e)

            except ResultFoundException as e:

                Logger.pl('{*} {GR}Checking with Fake Certificate chain{W}')

                res_path = str(Path(os.path.join(Configuration.path, 'certificates')).resolve())
                if not os.path.isdir(res_path):
                    os.mkdir(res_path)

                rnd = StringPart.random_string(8, 'S').decode("UTF-8")
                p12_name = os.path.join(res_path, f'pkcs12_{rnd}.pfx')
                exe_name = os.path.join(res_path, f'pkcs12_{rnd}.exe')

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
                    cwd=res_path
                )

                if status_code != 0:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot sign with the new certificates{W}')
                    if Configuration.verbose >= 3:
                        Logger.pl('{GR}%s{W}' % stderr)

                with open(exe_name, 'rb') as pe:
                    new_f_data = bytearray(pe.read())

                st5 = checker.check_file(
                        test_id=1,
                        name='Fake Digital Certificate',
                        hash=hashlib.md5(new_f_data).hexdigest().lower(),
                        crashed=not self._check_file(new_f_data),
                        data=new_f_data,
                        wait_time=self.sleep,
                        force_execution=True,
                )

                self.result_table[key]['tests']['Fake Certificate chain'] = 'clean' if st5 else 'flagged'

                if st5:
                    raise ResultFoundException()

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
                    if nores_data is not None and not self._is_equal(f_data, nores_data):
                        last_file = nores_data
                        st5 = checker.check_file(
                                test_id=1,
                                name=k,
                                hash=hashlib.md5(nores_data).hexdigest().lower(),
                                crashed=not self._check_file(nores_data),
                                data=nores_data,
                                wait_time=self.sleep,
                                force_execution=True,
                        )

                        self.result_table[key]['tests'][f"Original - {k}"] = 'clean' if st5 else 'flagged'

                    # Using incremental stripped file
                    nores_data = Tools.pe_strip_resources(f_data_incremental, res_check, error_on_equal=False)
                    if nores_data is not None and not self._is_equal(f_data_incremental, nores_data):
                        last_file = nores_data
                        st6 = checker.check_file(
                                test_id=1,
                                name=k,
                                hash=hashlib.md5(nores_data).hexdigest().lower(),
                                crashed=not self._check_file(nores_data),
                                data=nores_data,
                                wait_time=self.sleep,
                                force_execution=True,
                        )

                        self.result_table[key]['tests'][f"Incremental - {k}"] = 'clean' if st6 else 'flagged'

                        f_data_incremental = nores_data.copy()

                except ResultFoundException as e:
                    raise e
                except Exception as e:
                    self.result_table[key]['tests'][k] = 'error'
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip %s: {O}%s{W}' % (k, str(e)))
                    if Configuration.verbose >= 3:
                        Tools.print_error(e)

            self.result_table[key]['result'] = 'success'
        except ResultFoundException as ste:
            self.result_table[key]['result'] = 'success'
            return

    @classmethod
    def _is_equal(cls, data1, data2):
        return hashlib.md5(data1).hexdigest().lower() == hashlib.md5(data2).hexdigest().lower()

    @classmethod
    def _get_args(cls):
        return argparse.ArgumentParser(usage=argparse.SUPPRESS)

    def _get_std_checker(self, url: str, cmd: str = None):
        parser = self._get_args()
        checker = RemoteFile()
        checker.add_commands(parser)
        checker.add_flags(parser)
        checker.quiet = True
        checker.no_db = True

        args = parser.parse_args([
                                     "--api", url,
                                     "--execute",
                                     "-T", "1",
                                     "-sleep", f"{self.sleep}",
                                     "--initial-check"
                                 ] + (["--command", str(cmd)] if cmd is not None else []))
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

