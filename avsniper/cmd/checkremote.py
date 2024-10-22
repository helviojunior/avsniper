import errno
import hashlib
import json
import os
import re
import shutil
import sqlite3
import threading
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlparse

import hexdump
import requests
from clint.textui import progress

from avsniper.cmd.checker import Checker
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


class RemoteFile(Checker):
    help_show = True
    order = 30
    api_url = None
    cmd = None
    av_name = None
    os_info = None

    def __init__(self):
        super().__init__('check-remote', 'Check detected files using a remote server')

    def add_flags(self, flags: _ArgumentGroup):

        flags.add_argument('--api',
                           action='store',
                           dest='api_url',
                           metavar='[api_url]',
                           type=str,
                           help=Color.s('Url of the test server'))

        flags.add_argument('--command',
                           action='store',
                           dest='cmd',
                           metavar='[Command]',
                           type=str,
                           help=Color.s(('Custom command to execute at remote host. '
                                         'Put {G}{exe}{W} to be replaced by filename')))

        super().add_flags(flags)

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

        if re.match(regex, args.api_url) is None:
            Color.pl('{!} {R}error: invalid api url {O}%s{R}{W}\r\n' % args.api_url)
            exit(1)

        try:
            url = urlparse(args.api_url)
            self.api_url = f'{url.scheme}://{url.netloc}'
        except Exception as e:
            Color.pl('{!} {R}error: invalid api url {O}%s{R}: {O}%s{R}{W}\r\n' % (args.api_url, str(e)))
            exit(1)

        if not self.quiet:
            Logger.pl('     {C}url:{O} %s{W}' % self.api_url)

        self.cmd = args.cmd.strip(' ').strip('\t').strip('\r').strip(' ') if args.cmd is not None else None
        if self.cmd == "":
            self.cmd = None

        super().load_from_arguments(args)

        return True

    def run(self):
        Logger.pl('{+} {C}Checking connection with {O}%s{W}' % self.api_url)

        try:
            r1 = requests.get(f"{self.api_url}/api/v1/ping/",
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

        super().run()

    def check_file(self, test_id: int, name: Optional[str], hash: str,
                   crashed: bool = False, wait_time: float = 0.3,
                   data: Union[bytearray, bytes, str] = None,
                   force_execution: bool = False) -> bool:

        f_data = None

        if data is not None:
            if isinstance(data, bytearray):
                f_data = data
            elif isinstance(data, bytes):
                f_data = bytearray(data)
            elif isinstance(data, str):
                f_data = StringPart.b64decode(data)

        if f_data is None:

            p_src = os.path.join(Configuration.path, name)

            if not os.path.isfile(p_src):
                if Configuration.verbose >= 1:
                    Tools.clear_line()
                    Logger.pl('{*} {C}Local file not found: {GR}%s{W}' % name)
                return False

            try:
                with open(p_src, 'rb') as f:
                    f_data = f.read()

            except IOError as x:
                if x.errno == errno.EACCES:
                    if Configuration.verbose >= 2:
                        Tools.clear_line()
                        Logger.pl('{*} {C}could not open file "{O}%s{C}" {O}permission denied{W}' % name)
                    return False
                elif x.errno == errno.EISDIR:
                    if Configuration.verbose >= 2:
                        Tools.clear_line()
                        Logger.pl('{*} {C}could not open file "{O}%s{C}" {O}it is an directory{W}' % name)
                    return False
                else:
                    if Configuration.verbose >= 2:
                        Tools.clear_line()
                        Logger.pl('{*} {C}could not open file "{O}%s{C}"{W}' % name)
                    return False

        if f_data is None:
            return False

        data = dict(
            test_id=test_id,
            hash=hash,
            crashed=crashed,
            execute_exe=self.execute_exe or force_execution,
            wait_time=wait_time,
            data=StringPart.b64encode(f_data),
            command=self.cmd if self.cmd is not None else ""
        )

        r1 = None
        for idx in range(7):
            try:

                r1 = requests.post(f"{self.api_url}/api/v1/check_file/{test_id}/",
                                   verify=False,
                                   timeout=120,
                                   data=json.dumps(data),
                                   headers={
                                       'content-type': 'application/json'
                                   })

                break
            except requests.exceptions.ConnectionError as conne:
                if idx >= 5:
                    raise conne

                if 'An existing connection was forcibly closed by the remote host' in str(conne):
                    if Configuration.verbose >= 2:
                        Tools.clear_line()
                        Logger.pl('\n{!} {O}Warning checking file %s{O}: {GR}%s{O}, trying again...{W}' % (
                            name,
                            'An existing connection was forcibly closed by the remote host'
                        ))
                    time.sleep(0.5)
            except requests.exceptions.ReadTimeout as conne:
                if idx >= 5:
                    raise conne

                if 'timed out' in str(conne):
                    if Configuration.verbose >= 2:
                        Tools.clear_line()
                        Logger.pl('\n{!} {O}Warning checking file %s{O}: {GR}%s{O}, trying again...{W}' % (
                            name,
                            'Read timed out'
                        ))
                    time.sleep(0.5)

        if r1 is None:
            raise Exception('Error getting HTTP response: Response is None')

        if r1.status_code == 200:
            if Configuration.verbose >= 4:
                Tools.clear_line()
                try:
                    json_data = r1.json()
                    data['data'] = data['data'][0:16] + "..."
                    json_data = dict(request=data, response=json_data)
                    Tools.clear_line()
                    Logger.pl('{*} {C}JSON data response for test id {O}%s{C}: \n     {GR}%s{W}' % (
                        test_id, json.dumps(json_data).replace('\n', '\n     ')))
                except Exception as e:
                    raise Exception('Error parsing JSON result (%s): %s' % (str(e), str(r1.content)))
            return True

        if Configuration.verbose < 2:
            return r1.status_code == 200

        if Configuration.verbose >= 3:
            Tools.clear_line()
            Logger.pl('{*} {C}http status code for {O}%s{C}: {O}%s{C}{W}' % (name, r1.status_code))

        try:
            json_data = r1.json()
            if Configuration.verbose >= 4:
                data['data'] = data['data'][0:16] + "..."
                p_json_data = dict(request=data, response=json_data)
                Tools.clear_line()
                Logger.pl('{*} {C}JSON data response for test id {O}%s{C}: \n     {GR}%s{W}' % (
                    test_id, json.dumps(p_json_data).replace('\n', '\n     ')))
        except Exception as e:
            raise Exception('Error parsing JSON result (%s): %s' % (str(e), str(r1.content)))

        if not json_data.get('file_exists', False):
            if Configuration.verbose >= 3:
                Tools.clear_line()
                Logger.pl('{*} {C}File not found: {GR}%s{W}' % name)
            return False

        if not json_data.get('hash', False):
            if Configuration.verbose >= 3:
                Tools.clear_line()
                Logger.pl('{*} {C}Invalid file hash {O}%s{C}{W}' % name)
            return False

        if self.execute_exe and not json_data.get('execution', False):
            if Configuration.verbose >= 3:
                Tools.clear_line()
                Logger.pl('{*} {C}Execution error {O}%s{C}: {O}%s{C}{W}' % (name, json_data.get('execution_error', '')))
            return False

        return True

    def get_avname(self) -> str:

        if self.av_name is not None and self.av_name != 'Unknown':
            return self.av_name

        self.av_name = 'Unknown'

        self._get_avdata()

        return self.av_name

    def get_osinfo(self) -> str:

        if self.os_info is not None and self.os_info != 'Unknown':
            return self.os_info

        self.os_info = 'Unknown'

        self._get_avdata()

        return self.os_info

    def _get_avdata(self):
        try:

            r1 = requests.get(f"{self.api_url}/api/v1/av_name",
                               verify=False,
                               timeout=120,
                               headers={
                                   'content-type': 'application/json'
                               })

            if r1 is None:
                raise Exception('Error getting HTTP response: Response is None')

            if r1.status_code == 200:
                try:
                    json_data = r1.json()

                    self.av_name = json_data.get('av_data', {}).get('display_name', self.av_name)

                    os_info = json_data.get('os_info', None)
                    if os_info is not None and os_info.get('name', None) is not None:
                        self.os_info = ' '.join([
                            p for p in [
                                os_info.get('name', None),
                                os_info.get('version', None),
                                "Build",
                                os_info.get('build', "N/A")
                                ]
                            if p is not None
                            ])
                except Exception as e:
                    raise Exception('Error parsing JSON result (%s): %s' % (str(e), str(r1.content)))

            elif r1.status_code == 404:
                Logger.pl('{!} {GR}Error getting AV product information, update your Web Server script!{W}')

        except Exception as e:
            Logger.pl('{!} {GR}Error getting AV product information: {O}%s{W}' % str(e))
            if Configuration.verbose >= 2:
                Tools.print_error(e)

