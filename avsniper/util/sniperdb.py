#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import datetime
import sys, os.path
import sqlite3
import string, base64
import json
import hashlib
from pathlib import Path
from sqlite3 import Connection, OperationalError, IntegrityError, ProgrammingError

from .color import Color
from .database import Database
from .strings import StringPart


class SniperDB(Database):

    def __init__(self, auto_create=True, db_name=None):

        if db_name is None:
            db_name = "sniper.db"

        self.db_name = db_name

        super().__init__(
            auto_create=auto_create,
            db_name=db_name
        )

    def clone(self):
        return SniperDB(auto_create=False, db_name=self.db_name)

    def has_data(self) -> bool:
        return self.select_count('src_file') > 0

    def check_open(self) -> bool:
        return self.select_count('src_file') >= 0

    def insert_file(self, name: str, sha256_hash: str, md5_hash: str, data: bytearray, tags: str = '') -> int:

        s_name = Path(name).name
        enc = StringPart.b64encode(data)
        self.insert_update_one_exclude('src_file',
                                       exclude_on_update=['original_data'],
                                       name=s_name,
                                       sha256_hash=sha256_hash,
                                       md5_hash=md5_hash,
                                       data=enc,
                                       original_data=enc,
                                       finished='F',
                                       tags=tags
                                       )

        return int(self.select_first('src_file', name=s_name)['src_file_id'])

    def insert_string(self, file_id: int, string_part: StringPart):

        new_str = self.insert_update_one('string',
                                         src_file_id=file_id,
                                         address=string_part.address,
                                         virtual_address=string_part.virtual_address,
                                         section=string_part.section,
                                         dotnet='T' if string_part.is_dotnet_section else 'F',
                                         sha256_hash=string_part.sha256_hash,
                                         bytes_size=string_part.size,
                                         entropy=round(string_part.entropy, 2),
                                         encoding=str(string_part.encoding),
                                         encoded_string=string_part.encoded,
                                         flags=','.join(string_part.flags)
                                         )

        # Check if this string is already black listed in another file
        self.execute(sql=("insert or ignore into [black_list] (src_file_id, sha256_hash, encoded_string, encoding)"
                          "select ?, sha256_hash, encoded_string, encoding from [black_list]"
                          "where src_file_id != ? and sha256_hash == ?"),
                     args=[file_id, file_id, string_part.sha256_hash])

        return new_str

    def insert_test_file(self, string_id: int, file_id: int, type: str, file_name: str,
                         md5_hash: str, crashed: bool, strategy: int, **kwargs):

        additional_data = '{}'
        if isinstance(kwargs, dict) and kwargs is not None and len(kwargs) > 0:
            from .tools import Tools
            additional_data = json.dumps(kwargs, default=Tools.json_serial)

        return self.insert_update_one('test_file',
                                      string_id=string_id,
                                      src_file_id=file_id,
                                      type=type,
                                      file_name=file_name,
                                      md5_hash=md5_hash,
                                      crashed='T' if crashed else 'F',
                                      strategy=strategy,
                                      additional_data=additional_data
                                      )

    def insert_black_list(self, file_id: int, sha256_hash: str, encoding: str, encoded_string: str) -> dict:

        return self.insert_update_one('black_list',
                                      src_file_id=file_id,
                                      encoded_string=encoded_string,
                                      encoding=encoding,
                                      sha256_hash=sha256_hash,
                                      )

    def create_db(self):

        conn = self.connect_to_db(check=False)

        # definindo um cursor
        cursor = conn.cursor()

        # criando a tabela (schema)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [src_file] (
                src_file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                md5_hash TEXT NOT NULL,
                tags TEXT NOT NULL,
                data TEXT NOT NULL,
                original_data TEXT NULL,
                last_av TEXT NULL,
                finished varchar(1) NOT NULL DEFAULT('F'),
                UNIQUE(name),
                UNIQUE(sha256_hash)
            );
        """)

        conn.commit()

        # criando a tabela (schema)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [string] (
                string_id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_file_id INTEGER NOT NULL,
                parent_id INTEGER NOT NULL DEFAULT(-1),
                tree_idx INTEGER NOT NULL DEFAULT(0),
                section TEXT NOT NULL,
                address INTEGER NOT NULL,
                virtual_address INTEGER NOT NULL,
                bytes_size INTEGER NOT NULL,
                entropy DECIMAL(10,2) NOT NULL DEFAULT(0.0),
                sha256_hash TEXT NOT NULL,
                encoded_string TEXT NOT NULL,
                encoding varchar(1) NOT NULL DEFAULT('S'),
                dotnet varchar(1) NOT NULL DEFAULT('F'),
                flags TEXT NOT NULL,
                UNIQUE(src_file_id, address, sha256_hash)
            );
        """)

        conn.commit()

        # criando a tabela (schema)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [black_list] (
                bl_id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_file_id INTEGER NOT NULL,
                sha256_hash TEXT NOT NULL,
                encoded_string TEXT NOT NULL,
                encoding varchar(1) NOT NULL DEFAULT('S'),
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(src_file_id, sha256_hash)
            );
        """)

        conn.commit()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS [test_file] (
                test_id INTEGER PRIMARY KEY AUTOINCREMENT,
                string_id INTEGER NOT NULL,
                src_file_id INTEGER NOT NULL,
                type varchar(10) NOT NULL  DEFAULT('I'),
                file_name TEXT NOT NULL,
                md5_hash TEXT NOT NULL,
                crashed varchar(1) NOT NULL DEFAULT('F'),
                strategy INTEGER NOT NULL DEFAULT(0),
                flagged varchar(1) NOT NULL DEFAULT('F'),
                finished varchar(1) NOT NULL DEFAULT('F'),
                additional_data TEXT NOT NULL,
                UNIQUE(string_id, type)
            );
        """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_string_black_list_1
                    ON string (sha256_hash, encoding);
                """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_string_black_list_2
                    ON string (src_file_id, sha256_hash, encoding);
                """)

        conn.commit()

        cursor.execute("""
                    CREATE INDEX idx_string_black_list_3
                    ON black_list (sha256_hash, encoding);
                """)

        conn.commit()

        #Must get the constraints
        self.get_constraints()
