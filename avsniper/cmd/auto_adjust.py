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
from typing import Optional

import hexdump
from clint.textui import progress

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


class AutoAdjustStrings(CmdBase):
    db = None
    check_database = True
    t_line = ''
    t_header_prefix = ''
    black_list = False
    vs_path = None

    def __init__(self):
        super().__init__('auto-adjust', 'Auto adjust strings at the code')

    def add_flags(self, flags: _ArgumentGroup):

        flags.add_argument('--all',
                           action='store_true',
                           default=False,
                           dest=f'replace_all',
                           help=Color.s('Replace all strings (not only black listed) (default: {G}False{W})'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--vs-project-path',
                          action='store',
                          metavar='[path]',
                          type=str,
                          dest=f'vs_path',
                          help=Color.s('Full path of visual studio project'))

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.vs_path is None or args.vs_path.strip() == '' or \
                not os.path.exists(args.vs_path) or not os.path.isdir(args.vs_path):
            Logger.pl('{!} {R}error: path does not exists {O}%s{R} {W}\r\n' % (
                args.vs_path))
            exit(1)

        self.vs_path = Path(args.vs_path).resolve()

        Logger.pl('{+} {C}Visual Studio project path {O}%s{W}' % self.vs_path)

        self.db = self.open_db(args)

        self.black_list = not args.replace_all

        self.t_line = ' ' + ''.join([
            '%s──' % c for k, c in sorted(Color.gray_scale.items(), key=lambda x: x[0], reverse=True)
        ]) + Color.s('{W}\n')

        self.t_header_prefix = ' \033[38;5;52m=\033[38;5;88m=\033[38;5;124m=\033[38;5;160m=\033[38;5;196m> '

        return True

    def run(self):

        try:
            Logger.pl('{+} {C}Getting *.cs files list{W}')
            cs_files = [f for f in self._list_files(self.vs_path)]
            if len(cs_files) == 0:
                Logger.pl('{!} {R}error: Files with >cs extension not found at {O}%s{R} {W}\r\n' % (
                    str(self.vs_path)))
                exit(1)

            Logger.pl('{+} {C}Strings list{W}')

            sql = "select sf.name, sf.src_file_id, sf.sha256_hash, sf.tags from [src_file] sf "
            if self.black_list:
                sql += " where src_file_id in (select src_file_id from [black_list] group by src_file_id) "
            sql += "order by sf.name"

            db_src_data = self.db.select_raw(sql=sql, args=[])

            for f_row in db_src_data:

                tmp = '\n'.join([
                    Color.s("  {O}%s: {G}%s{W}" % (k, v)) for k, v in ({
                        'File': f_row['name'],
                        'SHA 256 Hash': f_row['sha256_hash'],
                        'Tags': f_row['tags'],
                    }).items()
                ]) + '\n'

                table = self.t_line
                table += tmp
                table += '\n'

                sql = ("select s.address, s.string_id as 'String Id', s.section, s.dotnet, "
                       "s.encoding, s.encoded_string, 0 as 'files replaced' "
                       "from [string] as s "
                       "left join [black_list] as bl "
                       "   on bl.src_file_id == s.src_file_id and bl.sha256_hash == s.sha256_hash "
                       "   and bl.encoding == s.encoding "
                       "where s.src_file_id = ? ")
                if self.black_list:
                    sql += " and bl.bl_id is not null "
                sql += (" group by s.address, s.string_id, s.section, s.dotnet, s.encoding, s.encoded_string "
                        " order by s.address ")
                db_strings = self.db.select_raw(sql=sql, args=[f_row['src_file_id']])
                db_data = [
                    {
                        'string' if k == 'encoded_string' else k:
                            ' 0x' + (''.join([f'{x:02x}' for x in struct.pack('>I', v)])).zfill(8)
                            if k == 'address' else StringsEncoding.get_human_text(v)
                            if k == 'encoding' else StringPart.b64decode_as_str(v, r['encoding'])
                            if k == 'encoded_string' else ('True' if v == 'T' else 'False')
                            if k == 'dotnet' else v

                        for k, v in r.items()
                    }
                    for r in db_strings
                ]
                str_data = {r['address']: r['string'] for r in db_data}

                with progress.Bar(label=" \033[0m\033[36mLooking up strings ",
                                  expected_size=len(db_data) * len(cs_files),
                                  show_percent=True,
                                  no_tty_every_percent=10,
                                  auto_hide_cursor=True) as bar:

                    try:
                        for file in cs_files:
                            f_data = None
                            try:
                                with open(str(file), 'rb') as f:
                                    f_data = f.read().decode("UTF-8").replace('\r', '')
                                    pass
                            except IOError as x:
                                if x.errno == errno.EACCES:
                                    Logger.pl(
                                        '{!} {R}error: could not open file {G}%s {O}permission denied{R}{W}\r\n' %
                                        file)
                                    continue
                                elif x.errno == errno.EISDIR:
                                    Logger.pl(
                                        '{!} {R}error: could not open file {G}%s {O}it is an directory{R}{W}\r\n' %
                                        file)
                                    continue
                                else:
                                    Logger.pl('{!} {R}error: could not open file {G}%s{W}\r\n' % file)
                                    continue

                            for k, s in str_data.items():
                                old = f'"{s}"'
                                old2 = f'@"{s}"'
                                new = "System.Text.Encoding.BigEndianUnicode.GetString(new byte[] { %s })" % \
                                      ', '.join([
                                          f'0x{x:02x}'
                                          for x in s.encode('utf-16-be')
                                      ])
                                if old in f_data and 'global::' not in f_data:
                                    for line in f_data.split('\n'):
                                        if old in line:
                                            f_data = f_data.replace(line,
                                                                    line.replace(old2, new)
                                                                    .replace(old, new)
                                                                    .replace('const ', 'public static ')
                                                                    .strip('\n') +
                                                                    f" //{s}\n")
                                    for r in db_data:
                                        if r['address'] == k:
                                            r['files replaced'] += 1

                            with open(str(file), 'wb') as f:
                                f.write(f_data.replace('\r', '').replace('\n', '\r\n').encode("UTF-8"))

                    except KeyboardInterrupt as e:
                        raise e
                    finally:
                        bar.hide = True
                        bar.no_tty_every_percent = None

                db_data = sorted([r for r in db_data if r['files replaced'] > 0],
                                 key=lambda x: x['files replaced'], reverse=True)

                if len(db_data) > 0:
                    table += Tools.get_ansi_tabulated(db_data, " ")
                else:
                    table += '\n{!} {R}Zero strings replaced{W}'

                table += '\n\n'
                Logger.pl(table)

        except KeyboardInterrupt as e:
            raise e

    def _list_files(self, path: Path, recursive: bool = True):
        here = str(path.resolve())
        files = [
            f
            for name in os.listdir(here)
            if os.path.isfile(os.path.join(here, name))
            and (f := Path(os.path.join(here, name)).resolve()) is not None
            and (ext := f.suffix.lower().strip('. ').lower()) is not None
            and ext == "cs"
        ]

        yield from files

        if recursive:
            dirs = [
                Path(os.path.join(here, name)).resolve()
                for name in os.listdir(here)
                if os.path.isdir(os.path.join(here, name))
            ]

            for d in dirs:
                yield from self._list_files(
                    path=d,
                    recursive=recursive)
