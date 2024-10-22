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


class CleanStrings(CmdBase):
    db = None
    check_database = True

    def __init__(self):
        super().__init__('clean', 'Clean already processed strings')

    def add_flags(self, flags: _ArgumentGroup):
        pass

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        self.db = self.open_db(args)

        return True

    def run(self):

        try:
            Logger.pl('{+} {C}Doing backup{W}')

            epoch = int(time.time())

            sql = f"CREATE TABLE [bkp_{epoch}_string] AS SELECT * FROM string"
            self.db.execute(sql=sql, args=[])

            Logger.pl('{+} {C}Cleaning up tables{W}')

            sql = ("delete from [string] "
                   "where string_id not in ("
                   "    select s.string_id from [black_list] as bl "
                   "    inner join [string] as s "
                   "        on s.src_file_id = bl.src_file_id "
                   "        and s.sha256_hash = bl.sha256_hash "
                   "        and s.encoding = bl.encoding "
                   ") and string_id in ("
                   "    select s.string_id from [test_file] as tf "
                   "    where tf.finished == 'T' and tf.flagged == 'F' "
                   ")")
            self.db.execute(sql=sql, args=[])

        except KeyboardInterrupt as e:
            raise e

