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
from clint.textui import progress

from avsniper.cmd.enumerate import EnumerateFile
from avsniper.cmd.strip import StripFile
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


class TransforBlackListToStrings(CmdBase):
    db = None
    check_database = True
    near = False

    def __init__(self):
        super().__init__('bl-to-str', 'Transform all blacklisted strings as file strings')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--near',
                           action='store',
                           type=int,
                           default=0,
                           dest=f'near',
                           help=Color.s('Save num of strings before/after each math (default: {G}0{W}).'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        self.near = args.near
        if self.near < 0:
            self.near = 0
        self.db = self.open_db(args)

        return True

    def run(self):

        try:

            cnt = self.db.select_raw(sql="select count(*) as cnt from [black_list]", args=[])[0]['cnt']
            if cnt == 0:
                Color.pl('{!} {R}error: black list is empty{W}\n\n')
                exit(1)

            Logger.pl('{+} {C}Doing backup{W}')

            epoch = int(time.time())

            sql = f"CREATE TABLE [bkp_{epoch}_string] AS SELECT * FROM string"
            self.db.execute(sql=sql, args=[])

            sql = f"CREATE TABLE [bkp_{epoch}_black_list] AS SELECT * FROM black_list"
            self.db.execute(sql=sql, args=[])

            sql = f"CREATE TABLE [bkp_{epoch}_test_file] AS SELECT * FROM test_file"
            self.db.execute(sql=sql, args=[])

            Logger.pl('{+} {C}Cleaning up tables{W}')

            if self.near > 0:
                sql = ("select s.string_id, ifnull(bl.bl_id, -1) as bl_id "
                       "from [string] as s "
                       "left join [black_list] as bl "
                       "    on bl.src_file_id == s.src_file_id "
                       "    and bl.sha256_hash == s.sha256_hash "
                       "    and bl.encoding == s.encoding "
                       "order by s.address asc ")
                db_data = self.db.select_raw(sql=sql, args=[])

                # First get just line row index
                rows_idx = [
                    idx + i for idx, row in enumerate(db_data) for i in range(1, self.near + 1)
                    if row['bl_id'] != -1
                ] + [
                    idx - i for idx, row in enumerate(db_data) for i in range(1, self.near + 1)
                    if row['bl_id'] != -1
                ]

                # Now, insert the range as black_list
                for string_id in [
                    row['string_id'] for idx, row in enumerate(db_data)
                    if idx in rows_idx
                ]:
                    sql = ("INSERT OR IGNORE INTO [black_list] (src_file_id, sha256_hash, encoded_string, encoding) "
                           "select src_file_id, sha256_hash, encoded_string, encoding "
                           "from [string] "
                           "where string_id == ?")
                    self.db.execute(sql=sql, args=[string_id])

            # finally delete all non blacklisted
            sql = ("delete from [string] "
                   "where string_id not in ("
                   "    select s.string_id from [black_list] as bl "
                   "    inner join [string] as s "
                   "        on s.src_file_id = bl.src_file_id "
                   "        and s.sha256_hash = bl.sha256_hash "
                   "        and s.encoding = bl.encoding "
                   ")")
            self.db.execute(sql=sql, args=[])

            self.db.execute(sql="delete FROM black_list", args=[])
            self.db.execute(sql="delete FROM test_file", args=[])

            # Calculate binary tree
            sql = "select count(distinct s.parent_id) as tree, count(distinct s.string_id) as rows from [string] as s"
            row = self.db.select_raw(sql=sql, args=[])
            EnumerateFile.calculate_binary_tree(
                self.db,
                row[0]['tree'] <= 1 or row[0]['rows'] <= 50)

        except KeyboardInterrupt as e:
            raise e

