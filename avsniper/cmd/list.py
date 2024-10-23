import datetime
import errno
import hashlib
import os
import shutil
import sqlite3
import struct
import threading
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from typing import Optional

import hexdump
from avsniper.util import progress

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


class ListStrings(CmdBase):
    db = None
    check_database = True
    t_line = ''
    t_header_prefix = ''
    black_list = False

    def __init__(self):
        super().__init__('list', 'list all strings')

    def add_flags(self, flags: _ArgumentGroup):

        flags.add_argument('--black-list',
                           action='store_true',
                           default=False,
                           dest=f'black_list',
                           help=Color.s('Show only black listed strings (default: {G}False{W})'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        self.db = self.open_db(args)

        self.black_list = args.black_list

        self.t_line = ' ' + ''.join([
            '%s──' % c for k, c in sorted(Color.gray_scale.items(), key=lambda x: x[0], reverse=True)
        ]) + Color.s('{W}\n')

        self.t_header_prefix = ' \033[38;5;52m=\033[38;5;88m=\033[38;5;124m=\033[38;5;160m=\033[38;5;196m> '

        return True

    def run(self):

        try:
            Logger.pl('{+} {C}Strings list{W}')

            sql = "select sf.name, sf.src_file_id, sf.sha256_hash, sf.tags, sf.last_av from [src_file] sf "
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
                        'Last tested AV': f_row['last_av'],
                    }).items()
                ]) + '\n'

                table = self.t_line
                table += tmp
                table += '\n'

                sql = ("select s.address, s.string_id as 'String Id', s.section, s.dotnet, s.entropy, "
                       "s.encoding, s.encoded_string "
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
                        k:
                            ' 0x' + (''.join([f'{x:02x}' for x in struct.pack('>I', v)])).zfill(8)
                            if k == 'address' else StringsEncoding.get_human_text(v)
                            if k == 'encoding' else StringPart.b64decode_as_str(
                                v, r['encoding']).replace("\n", "\\n").replace("\r", "\\r")
                            if k == 'encoded_string' else ('True' if v == 'T' else 'False')
                            if k == 'dotnet' else v

                        for k, v in r.items()
                    }
                    for r in db_strings
                ]

                table += Tools.get_ansi_tabulated(db_data, " ")
                table += '\n\n'
                Logger.pl(table)

        except KeyboardInterrupt as e:
            raise e

