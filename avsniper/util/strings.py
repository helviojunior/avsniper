import base64
import hashlib
import json
import os
import random
import re
import string
import unicodedata
from enum import Enum
from functools import reduce
from struct import pack
from typing import TypeVar, Optional, Union
import io
from uuid import UUID

import hexdump
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Certificate
from cryptography import x509

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.libs.ca import CA
from avsniper.libs.pyinstaller import PyInstArchive
from avsniper.util.logger import Logger
from avsniper.util.microsoft_pe_holder import MicrosoftPeHolder
from avsniper.util.tools import Tools

TStrings = TypeVar("TStrings", bound="Strings")
TStringsEncoding = TypeVar("TStringsEncoding", bound="StringsEncoding")


class StringsEncoding(Enum):
    single_7_bit_byte = 0
    single_8_bit_byte = 1
    bigendian_16_bit = 2
    littleendian_16_bit = 3
    bigendian_32_bit = 4
    littleendian_32_bit = 5

    # Possible values for encoding are:
    #  s = single-7-bit-byte characters (ASCII, ISO 8859, etc., default)
    #  S = single-8-bit-byte characters
    #  b = 16-bit bigendian
    #  l = 16-bit littleendian
    #  B = 32-bit bigendian
    #  L = 32-bit littleendian.
    #
    #  Useful for finding wide character strings. (l and b apply to, for example, Unicode UTF-16/UCS-2 encodings).

    @classmethod
    def parse(cls, encoding: Union[TStringsEncoding, str]):
        if isinstance(encoding, StringsEncoding):
            return encoding

        if isinstance(encoding, str) and encoding == 's':
            return StringsEncoding.single_7_bit_byte
        elif isinstance(encoding, str) and encoding == 'S':
            return StringsEncoding.single_8_bit_byte
        elif isinstance(encoding, str) and encoding == 'b':
            return StringsEncoding.bigendian_16_bit
        elif isinstance(encoding, str) and encoding == 'l':
            return StringsEncoding.littleendian_16_bit
        elif isinstance(encoding, str) and encoding == 'B':
            return StringsEncoding.bigendian_32_bit
        elif isinstance(encoding, str) and encoding == 'L':
            return StringsEncoding.littleendian_32_bit
        else:
            raise Exception('Invalid encoding')

    @classmethod
    def get_human_text(cls, encoding: Union[TStringsEncoding, str]):
        if isinstance(encoding, StringsEncoding):
            e = encoding
        else:
            e = cls.parse(encoding)

        c = {
            StringsEncoding.single_7_bit_byte: 'ASCII',
            StringsEncoding.single_8_bit_byte: 'UTF-8',
            StringsEncoding.bigendian_16_bit: 'UTF-16 BE',
            StringsEncoding.littleendian_16_bit: 'UTF-16 LE',
            StringsEncoding.bigendian_32_bit: 'UTF-32 BE',
            StringsEncoding.littleendian_32_bit: 'UTF-32 LE'
        }
        return c[e]

    def to_encoding(self) -> str:
        c = {
            StringsEncoding.single_7_bit_byte: 'ascii',
            StringsEncoding.single_8_bit_byte: 'utf-8',
            StringsEncoding.bigendian_16_bit: 'utf-16-be',
            StringsEncoding.littleendian_16_bit: 'utf-16-le',
            StringsEncoding.bigendian_32_bit: 'utf-32-be',
            StringsEncoding.littleendian_32_bit: 'utf-32-le'
        }
        return c[self]

    def __str__(self):
        c = {
            StringsEncoding.single_7_bit_byte: 's',
            StringsEncoding.single_8_bit_byte: 'S',
            StringsEncoding.bigendian_16_bit: 'b',
            StringsEncoding.littleendian_16_bit: 'l',
            StringsEncoding.bigendian_32_bit: 'B',
            StringsEncoding.littleendian_32_bit: 'L'
        }
        return c[self]


class StringPart(object):
    data: bytearray
    address: int
    virtual_address: int
    size: int
    encoding: StringsEncoding
    section: str
    is_dotnet_section: bool
    flags: list[str]

    def __init__(self, data: Union[bytearray, bytes], address: int, virtual_address: int, size: int,
                 encoding: StringsEncoding, section: str = '', is_dotnet_section: bool = False,
                 flags: list[str] = []):
        self.data = bytearray(data)
        self.address = address
        self.virtual_address = virtual_address
        self.size = size
        self.encoding = encoding
        self.section = section
        self.is_dotnet_section = is_dotnet_section
        self.flags = flags

    def __str__(self):
        return f"Address: 0x{self.address:X}, Size: {self.size}, .NET: {self.is_dotnet_section}"

    def hexdump(self) -> str:
        if self.data is None or len(self.data) == 0:
            return ''
        return hexdump.hexdump(self.data, result='return')

    def decode(self) -> str:
        return StringPart.sdecode(self.data, self.encoding)

    @property
    def encoded(self) -> str:
        self.check_alignment()
        return StringPart.b64encode(self.data)

    @property
    def entropy(self) -> float:
        # https://en.wiktionary.org/wiki/Shannon_entropy
        from math import log2

        s_data = StringPart.sdecode(self.data, self.encoding)
        data = unicodedata.normalize('NFD', s_data) \
            .encode('utf-8', 'ignore')

        if len(data) == 0:
            return 0.0

        counters = {byte: 0 for byte in range(2 ** 8)}  # start all counters with zeros

        for byte in data:
            counters[byte] += 1

        probabilities = [counter / len(data) for counter in counters.values()]  # calculate probabilities for each byte

        en = -sum(
            probability * log2(probability) for probability in probabilities if probability > 0)  # final sum

        return round(en, 2)

    def check_alignment(self):
        if self.encoding in [StringsEncoding.bigendian_32_bit, StringsEncoding.littleendian_32_bit]:
            encoding_bytes = 4
        elif self.encoding in [StringsEncoding.bigendian_16_bit, StringsEncoding.littleendian_16_bit]:
            encoding_bytes = 2
        else:
            encoding_bytes = 1

        # One final nullbyte
        pad = (len(self.data) % encoding_bytes)
        if pad > 0:
            self.data += bytearray(
                [0x00 for _ in range(0, pad)]
            )

    def strip(self):
        # Check common rules as exemples bellow
        #  &https://www.globalsign.com/repository/0
        #  ZSystem.Object
        s_data = self.decode()
        new_data = bytearray()
        if (m := re.search(r'(http[s]{0,1}://.*)', s_data)) is not None and 0 < m.lastindex <= 2:
            new_data = StringPart.encode(m.group(1), self.encoding)
        elif (m := re.search(r'(System\..*)', s_data)) is not None and 0 < m.lastindex <= 2:
            new_data = StringPart.encode(m.group(1), self.encoding)
        else:
            return

        if len(new_data) == 0:
            return

        idx = self.data.find(new_data)
        if idx == -1:
            return

        self.data = new_data
        self.size = len(self.data)
        self.address += idx

    @property
    def sha256_hash(self) -> str:
        self.check_alignment()
        return hashlib.sha256(self.data).hexdigest().lower()

    @staticmethod
    def b64encode(s: Union[bytes, str]) -> str:
        if isinstance(s, str):
            s = s.encode("UTF-8")
        d1 = base64.b64encode(s)
        if isinstance(d1, bytes):
            d1 = d1.decode('utf-8')

        b_data = bytearray(d1.encode('utf-16-be'))
        for i in range(0, len(b_data)):
            b_data[i] = b_data[i] ^ 0x4d

        b64_data = base64.b64encode(b_data)
        if isinstance(b64_data, bytes):
            b64_data = b64_data.decode('utf-8')

        return b64_data

    @staticmethod
    def b64decode(s: Union[bytes, str]) -> bytearray:
        b_data = bytearray(base64.b64decode(s))
        for i in range(0, len(b_data)):
            b_data[i] = b_data[i] ^ 0x4d
        s_data = b_data.decode('utf-16-be')

        return bytearray(base64.b64decode(s_data))

    @staticmethod
    def b64decode_as_str(s: Union[bytes, str], encoding: Union[str, StringsEncoding]) -> str:
        b_data = bytearray(StringPart.b64decode(s))
        s_data = ''.join([
            c if Tools.permited_char(c) else f'\\x{ord(c):02x}'
            for c in StringPart.sdecode(b_data, encoding).encode('latin-1', 'ignore').decode("latin-1")
        ])

        return s_data

    @staticmethod
    def sdecode(data: Union[bytes, bytearray], encoding: Union[str, StringsEncoding]) -> str:

        if not isinstance(encoding, StringsEncoding):
            encoding = StringsEncoding.parse(encoding)

        data = b'' + data

        # https://docs.python.org/3/library/codecs.html#standard-encodings
        if encoding in [StringsEncoding.bigendian_32_bit]:
            return data.decode('utf-32-be', errors='strict')
        elif encoding in [StringsEncoding.littleendian_32_bit]:
            return data.decode('utf-32-le', errors='strict')
        elif encoding in [StringsEncoding.bigendian_16_bit]:
            return data.decode('utf-16-be', errors='strict')
        elif encoding in [StringsEncoding.littleendian_16_bit]:
            return data.decode('utf-16-le', errors='strict')
        else:
            try:
                return data.decode('utf-8', errors='strict')
            except:
                return data.decode('latin-1', errors='strict')

    @staticmethod
    def encode(data: str, encoding: Union[str, StringsEncoding]) -> bytearray:

        if not isinstance(encoding, StringsEncoding):
            encoding = StringsEncoding.parse(encoding)

        # https://docs.python.org/3/library/codecs.html#standard-encodings
        if encoding in [StringsEncoding.bigendian_32_bit]:
            return bytearray(data.encode('utf-32-be'))
        elif encoding in [StringsEncoding.littleendian_32_bit]:
            return bytearray(data.encode('utf-32-le'))
        elif encoding in [StringsEncoding.bigendian_16_bit]:
            return bytearray(data.encode('utf-16-be'))
        elif encoding in [StringsEncoding.littleendian_16_bit]:
            return bytearray(data.encode('utf-16-le'))
        else:
            try:
                return bytearray(data.encode('utf-8'))
            except:
                return bytearray(data.encode('latin-1'))

    @staticmethod
    def random_string(raw_size: int, encoding: Union[StringsEncoding, str]) -> bytearray:
        e = StringsEncoding.parse(encoding)
        if e in [StringsEncoding.bigendian_32_bit, StringsEncoding.littleendian_32_bit]:
            encoding_bytes = 4
        elif e in [StringsEncoding.bigendian_16_bit, StringsEncoding.littleendian_16_bit]:
            encoding_bytes = 2
        else:
            encoding_bytes = 1

        if raw_size % encoding_bytes != 0:
            raise Exception('Invalid boundary size')

        s_rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(1))
        s_rnd += ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.ascii_letters)
                         for x in range(int(raw_size / encoding_bytes) - 1))

        b_data = bytearray(s_rnd.encode(e.to_encoding()))

        # sanity check
        if raw_size != len(b_data):
            raise Exception((f"Invalid random string result size: "
                             f"Generated {len(b_data)}, expected {raw_size} bytes"))

        return b_data


class Strings(object):
    data: io.BytesIO = None
    encoding = StringsEncoding.single_8_bit_byte
    include_all_whitespace = True
    offset = 0
    encoding_bytes = 1
    pe_file = None
    debug = False

    ascii_table = string.ascii_lowercase + string.ascii_lowercase + \
                  string.ascii_letters + string.digits + string.punctuation

    def __init__(self, data: bytearray, include_all_whitespace: bool = True):
        self.data = io.BytesIO(data)
        self.include_all_whitespace = include_all_whitespace
        self.parse_from_type(data)

    def parse_from_type(self, data: bytearray):
        mz = b"MZ"
        elf = b"\x7FELF"
        macho = pack("I", 0xfeedfacf)

        if data[0x0:0x2] == mz:
            self.pe_file = MicrosoftPe.from_bytes(data)
        elif data[0x0:0x4] == elf:
            pass
        elif data[0x0:0x4] == macho:
            pass

    def reset(self):
        self.data.seek(0)

    def decode(self, c: int) -> str:
        # https://docs.python.org/3/library/codecs.html#standard-encodings

        if self.encoding in [StringsEncoding.bigendian_32_bit, StringsEncoding.littleendian_32_bit]:
            return c.to_bytes(length=4, byteorder='big').decode('utf-32-be', errors='strict')
        elif self.encoding in [StringsEncoding.bigendian_16_bit, StringsEncoding.littleendian_16_bit]:
            return c.to_bytes(length=2, byteorder='big').decode('utf-16-be', errors='strict')
        else:
            try:
                return c.to_bytes(length=1, byteorder='big').decode('utf-8', errors='strict')
            except:
                return c.to_bytes(length=1, byteorder='big').decode('latin-1', errors='strict')

    def string_is_graphic(self, c: int) -> bool:
        #c1 = self.extract(c)
        c1 = c
        return (
                0 <= c <= 127   # change from 127 to 255 to enable non printable ASCII
                and (
                        (self.encoding != StringsEncoding.single_7_bit_byte)
                        or (self.encoding == StringsEncoding.single_7_bit_byte and c <= 127)
                )
                and c1 not in [0x09, 0x0a, 0x0d]  # \t, \n, \r
                and self.is_print(c1)
        )

    def extract(self, c: int) -> int:
        try:

            if self.encoding == StringsEncoding.single_7_bit_byte and (c & 0xf0) == 0x00:
                return c & 0x7f
            elif self.encoding == StringsEncoding.single_8_bit_byte:
                return c & 0xff
            elif self.encoding in [StringsEncoding.bigendian_16_bit, StringsEncoding.littleendian_16_bit] \
                    and (c & 0xff00) == 0x00:
                return c & 0xff
            elif self.encoding in [StringsEncoding.bigendian_32_bit, StringsEncoding.littleendian_32_bit] \
                    and (c & 0xffffff00) == 0x00:
                return c & 0xff
            else:

                # look for specific exceptions

                # in some parts of code the endianess of ' and " is wrong
                if self.encoding in [StringsEncoding.bigendian_16_bit, StringsEncoding.littleendian_16_bit] \
                        and (c & 0x00ff) == 0x00:
                    if (t := (c & 0xff00) >> 8) in [0x27, 0x22]:  # ' and "
                        return t

                return 0x00
        except Exception as e:
            return c

    def is_print(self, c: int):

        try:
            if c == 0x20:
                if self.include_all_whitespace:
                    return True
                else:
                    return False

            s = chr(c & 0xff)

            if s in ['\r', '\n', '\t']:
                return False
            elif s.isprintable():
                return True
            elif s.isalpha():
                return True
            elif bool(re.match("^[A-Za-z0-9]*$", s)):
                return True
            elif s == "-":
                return True
            elif s == "_":
                return True
            elif s == ".":
                return True
            elif s == "\t":
                return True
            else:
                return False
        except:
            return False

    def get_char(self) -> Optional[int]:
        r = 0
        for i in range(0, self.encoding_bytes):
            c = self.data.read(1)
            if c is None or len(c) == 0:
                return None

            c = c[0]

            r = (r << 8) | (c & 0xff)

        if self.encoding == StringsEncoding.littleendian_16_bit:
            r = ((r & 0xff) << 8) | ((r & 0xff00) >> 8)
        elif self.encoding == StringsEncoding.littleendian_32_bit:
            r = (((r & 0xff) << 24) | ((r & 0xff00) << 8)
                 | ((r & 0xff0000) >> 8) | ((r & 0xff000000) >> 24))

        return r

    def unget_char(self, size: int = -1):
        p = self.data.tell()
        if size == -1:
            size = self.encoding_bytes
        self.data.seek(p - size)

    def parse_as_dotnet(self) -> bool:
        return (
                self.pe_file.pe.optional_hdr.data_dirs.clr_runtime_header is not None
                and self.pe_file.pe.optional_hdr.data_dirs.clr_runtime_header.size >= 0x48
                and self.pe_file.pe.dotnet_header is not None
                and self.pe_file.pe.dotnet_metadata_header is not None
                and self.pe_file.pe.dotnet_metadata_header.streams is not None
                and len(self.pe_file.pe.dotnet_metadata_header.streams) > 0
        )

    def get_strings(self,
                    encoding: [StringsEncoding, str] = StringsEncoding.single_8_bit_byte,
                    string_min: int = 3, threshold: int = 70, min_entropy: float = 1.0,
                    parse_dotnet: bool = True, raw_binary: bool = False, check_overlay: bool = True):

        from avsniper.config import Configuration

        if isinstance(encoding, str):
            self.encoding = StringsEncoding.parse(encoding)
        else:
            self.encoding = encoding

        if self.encoding in [StringsEncoding.bigendian_32_bit, StringsEncoding.littleendian_32_bit]:
            self.encoding_bytes = 4
        elif self.encoding in [StringsEncoding.bigendian_16_bit, StringsEncoding.littleendian_16_bit]:
            self.encoding_bytes = 2

        if not raw_binary and self.pe_file is not None \
                and self.pe_file.pe.sections is not None and len(self.pe_file.pe.sections) > 0:

            base_addr = 0
            if self.pe_file.pe.optional_hdr.std.format.value == 0x10b:
                base_addr = self.pe_file.pe.optional_hdr.windows.image_base_32
            elif self.pe_file.pe.optional_hdr.std.format.value == 0x20b:
                base_addr = self.pe_file.pe.optional_hdr.windows.image_base_64

            skip_resources = (self.pe_file.pe.resources_table is not None
                              and (self.pe_file.pe.resources_table.number_of_named_entries > 0
                                   or self.pe_file.pe.resources_table.number_of_id_entries > 0))

            # Native PE file (Ex: C, C++...)
            Tools.clear_line()
            Logger.pl('{*} {GR}Parsing {O}native PE file{GR} using {O}%s{GR} encoding{W}' %
                      StringsEncoding.get_human_text(self.encoding))

            for section in self.pe_file.pe.sections:
                if (section.name != '.rsrc' or not skip_resources) and section.name != '.reloc':
                    yield from self.get_strings_raw(
                        offset=section.pointer_to_raw_data,
                        va_offset=base_addr + (section.virtual_address - section.pointer_to_raw_data),
                        size=section.virtual_size,
                        threshold=threshold,
                        string_min=string_min,
                        min_entropy=min_entropy,
                        section_name=Tools.clear_string(section.name),
                        is_dotnet_section=False
                    )

            # Resource
            if skip_resources:
                for res in self.pe_file.pe.resources_table.items:
                    if res.is_directory and res.directory_table is not None:
                        for res1 in res.directory_table.items:
                            if res1.is_directory and res1.directory_table is not None:
                                for res2 in res1.directory_table.items:
                                    if res2.is_data_entry and res2.data_size > 0 and res2.pointer_to_raw_data > 0:

                                        if res.name_type in [MicrosoftPe.DirectoryEntryType.manifest]:

                                            self.data.seek(res2.pointer_to_raw_data)
                                            yield StringPart(
                                                data=bytearray(self.data.read(res2.data_size)),
                                                address=res2.pointer_to_raw_data,
                                                virtual_address=base_addr + (
                                                        res2.virtual_address - res2.pointer_to_raw_data),
                                                size=res2.data_size,
                                                encoding=StringsEncoding.single_8_bit_byte,
                                                section='rsrc',
                                                is_dotnet_section=False
                                            )

                                        else:

                                            yield from self.get_strings_raw(
                                                offset=res2.pointer_to_raw_data,
                                                va_offset=base_addr + (
                                                        res2.virtual_address - res2.pointer_to_raw_data),
                                                size=res2.data_size,
                                                string_min=string_min,
                                                min_entropy=min_entropy,
                                                threshold=threshold,
                                                section_name='.rsrc',
                                                is_dotnet_section=False
                                            )

            if parse_dotnet and self.parse_as_dotnet():
                # .NET File
                Tools.clear_line()
                Logger.pl('{*} {GR}Parsing {O}.NET PE file{GR} using {O}%s{GR} encoding{W}' %
                          StringsEncoding.get_human_text(self.encoding))

                for section in self.pe_file.pe.dotnet_metadata_header.streams:

                    if Configuration.verbose >= 4:
                        Logger.pl('{*} {GR}Parsing {O}.NET PE section %s{GR}{W}' %
                                  Tools.clear_string(section.name))

                    yield from self.get_strings_raw(
                        offset=section.pointer_to_raw_data,
                        va_offset=base_addr + (
                                self.pe_file.pe.optional_hdr.data_dirs.resource_table.virtual_address -
                                section.pointer_to_raw_data),
                        size=section.size,
                        string_min=string_min,
                        min_entropy=min_entropy,
                        section_name=Tools.clear_string(section.name),
                        is_dotnet_section=True
                    )

            # Certificates (Raw memory)
            try:
                for cd in Tools.pe_certificate_positions(self.pe_file):
                    yield from self.get_strings_raw(
                        offset=cd['start_addr'],
                        va_offset=cd['start_addr'],
                        size=cd['size'],
                        string_min=string_min,
                        min_entropy=min_entropy,
                        threshold=threshold,
                        section_name='.rsrc',
                        is_dotnet_section=False,
                        flags=['cert']
                    )
            except:
                pass

            # Parsed strings from Certificates
            try:
                yield from Strings.get_certificate_strings(
                    data=self.pe_file,
                    string_min=string_min,
                    threshold=threshold)
            except:
                pass

            # check overlay (data after PE structure)
            if check_overlay and (overlay := Tools.pe_overlay_data(self.pe_file))['has_ovarlay'] is True:
                Tools.clear_line()

                try:
                    # check if is a PyInstaller file
                    pyinst = PyInstArchive(self.pe_file)
                    Logger.pl('{*} {GR}Parsing {O}PE file PyInstall overlay{GR} using {O}%s{GR} encoding{W}' %
                              StringsEncoding.get_human_text(self.encoding))
                    for f in pyinst.tocList:
                        if f.cmprsdDataSize >= string_min:
                            if f.cmprsdDataSize > 1024:
                                yield StringPart(
                                    data=bytearray(b''),
                                    address=f.position,
                                    virtual_address=f.position,
                                    size=0,
                                    encoding=self.encoding,
                                    section=f'PyInstaller {f.name}',
                                    is_dotnet_section=False
                                )
                            yield from self.get_strings_raw(
                                offset=f.position,
                                va_offset=f.position,
                                size=f.cmprsdDataSize,
                                threshold=threshold,
                                string_min=string_min,
                                min_entropy=min_entropy,
                                section_name=f'PyInstaller {f.name}',
                                is_dotnet_section=False
                            )
                            if f.cmprsdDataSize > 1024:
                                yield StringPart(
                                    data=bytearray(b''),
                                    address=f.position + f.cmprsdDataSize,
                                    virtual_address=f.position + f.cmprsdDataSize,
                                    size=0,
                                    encoding=self.encoding,
                                    section=f'PyInstaller {f.name}',
                                    is_dotnet_section=False
                                )
                    pyinst.close()
                except Exception as ex:
                    Logger.pl('{*} {GR}Parsing {O}PE file raw overlay{GR} using {O}%s{GR} encoding{W}' %
                              StringsEncoding.get_human_text(self.encoding))
                    #Tools.print_error(ex, force=True)
                    if overlay['size'] > 1024:
                        yield StringPart(
                            data=bytearray(b''),
                            address=overlay['start_addr'],
                            virtual_address=overlay['start_addr'],
                            size=0,
                            encoding=self.encoding,
                            section=f'Overlay',
                            is_dotnet_section=False
                        )
                    yield from self.get_strings_raw(
                        offset=overlay['start_addr'],
                        va_offset=overlay['start_addr'],
                        size=overlay['size'],
                        threshold=threshold,
                        string_min=string_min,
                        min_entropy=min_entropy,
                        section_name='Overlay',
                        is_dotnet_section=False
                    )
                    pass

        else:
            Tools.clear_line()
            Logger.pl('{*} {GR}Parsing {O}raw data{GR} using {O}%s{GR} encoding{W}' %
                      StringsEncoding.get_human_text(self.encoding))

            yield from self.get_strings_raw(
                offset=0,
                va_offset=0,
                size=self.data.getbuffer().nbytes,
                string_min=string_min,
                threshold=threshold,
                min_entropy=min_entropy,
                is_dotnet_section=False
            )

    def get_strings_raw(self,
                        offset: int, va_offset: int, size: int,
                        string_min: int = 3,
                        threshold: int = 10,
                        min_entropy: float = 1.0,
                        section_name: str = 'raw',
                        is_dotnet_section: bool = False,
                        flags: list[str] = []
                        ):

        yield from self._get_strings_raw(
            offset=offset,
            va_offset=va_offset,
            size=size,
            string_min=string_min,
            threshold=threshold,
            min_entropy=min_entropy,
            section_name=section_name,
            is_dotnet_section=is_dotnet_section,
            flags=flags
        )

        if self.encoding in [StringsEncoding.littleendian_16_bit, StringsEncoding.littleendian_32_bit]:
            # Deslocate 1 byte
            yield from self._get_strings_raw(
                offset=offset + 1,
                va_offset=va_offset + 1,
                size=size - 1,
                string_min=string_min,
                threshold=threshold,
                min_entropy=min_entropy,
                section_name=section_name,
                is_dotnet_section=is_dotnet_section,
                flags=flags
            )

    @staticmethod
    def _is_permitted(string_part: StringPart) -> bool:

        # check common strings to be ignored
        s_data = string_part.decode()

        if 'urn:schemas-microsoft-com' in s_data:
            return False
        elif 'schemas.microsoft.com' in s_data:
            return False
        elif 'schemas.openxmlformats.org' in s_data:
            return False
        elif '.NETFramework,Version=' in s_data:
            return False
        elif '.NET Framework' in s_data:
            return False
        elif '<assemblyIdentity version=' in s_data:
            return False
        elif 'Culture=neutral' in s_data:
            return False

        return True

    def _get_strings_raw(self,
                         offset: int, va_offset: int, size: int,
                         string_min: int = 3,
                         threshold: int = 10,
                         min_entropy: float = 1.0,
                         section_name: str = 'raw',
                         is_dotnet_section: bool = False,
                         flags: list[str] = []):

        byteorder = 'big' if self.encoding in [
            StringsEncoding.bigendian_16_bit,
            StringsEncoding.bigendian_32_bit] else 'little'

        addr = offset
        self.data.seek(addr)
        end_addr = offset + size
        t_str = StringPart(bytearray(), addr, va_offset + addr, 0,
                           self.encoding, section=section_name, is_dotnet_section=is_dotnet_section, flags=flags)

        while addr < end_addr:
            addr = self.data.tell()
            c = self.get_char()
            if c is None or addr == end_addr:
                t_str.size = self.data.tell() - t_str.address
                if t_str.size >= string_min and \
                        len(t_str.data) >= string_min and \
                        (threshold == 0 or Strings.ascii_count(t_str) >= threshold) and \
                        t_str.entropy >= min_entropy and \
                        Strings._is_permitted(t_str):
                    yield t_str
                break

            if not self.string_is_graphic(c):
                if t_str.size >= string_min and \
                        len(t_str.data) >= string_min and \
                        (threshold == 0 or Strings.ascii_count(t_str) >= threshold) and \
                        t_str.entropy >= min_entropy and \
                        Strings._is_permitted(t_str):
                    yield t_str
                t_str = StringPart(bytearray(),
                                   addr + self.encoding_bytes,
                                   va_offset + addr + self.encoding_bytes,
                                   0, self.encoding,
                                   section=section_name, is_dotnet_section=is_dotnet_section, flags=flags)
            else:
                try:
                    t_str.data += bytearray(c.to_bytes(length=self.encoding_bytes, byteorder=byteorder))
                    t_str.size = self.data.tell() - t_str.address
                except:
                    # step 1 byte over
                    if self.encoding_bytes > 1:
                        self.unget_char(self.encoding_bytes - 1)

    @staticmethod
    def ascii_count(text: Union[str, StringPart, bytes]) -> int:
        if isinstance(text, bytes):
            text = text.decode("UTF-8", "ignore")
        if isinstance(text, StringPart):
            text = text.decode()
        return reduce(lambda a, c: a + 1 if c in Strings.ascii_table else a, text, 0)

    @staticmethod
    def get_certificate_strings(data: Union[bytes, str, MicrosoftPe],
                                string_min: int = 3,
                                threshold: int = 10):

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.certificate_table is None:
            return

        # Do not imply/filter entropy to this method
        # it permit enumerate certificate serial number and etc...

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        for idx, cert_entry in enumerate(pe_file.pe.certificate_table.items):

            certificate_bytes = bytearray(cert_entry.certificate_bytes)

            try:
                attrs = CA.get_pkcs7_human_data(certificate_bytes)
                yield from [
                    StringPart(
                        data=v,
                        address=cert_entry.pointer_to_raw_data + offset,
                        virtual_address=cert_entry.pointer_to_raw_data + offset,
                        size=len(v),
                        encoding=StringsEncoding.single_8_bit_byte,
                        section='security',
                        is_dotnet_section=False,
                        flags=['cert']
                    )
                    for v in attrs
                    if v is not None
                       and not isinstance(v, dict)
                       and len(v) > string_min
                       and (threshold == 0 or Strings.ascii_count(v) >= threshold)
                       and (offset := certificate_bytes.find(bytearray(v)
                                                             if isinstance(v, bytes)
                                                             else str(v).encode("UTF-8"))) >= -1
                ]

                yield from [
                    StringPart(
                        data=v,
                        address=cert_entry.pointer_to_raw_data + offset,
                        virtual_address=cert_entry.pointer_to_raw_data + offset,
                        size=len(v),
                        encoding=StringsEncoding.single_8_bit_byte,
                        section='security',
                        is_dotnet_section=False,
                        flags=['cert']
                    )
                    for k, v1 in enumerate(attrs) for v in attrs[v1]
                    if v is not None
                       and isinstance(v1, dict)
                       and not isinstance(v, dict)
                       and len(v) > string_min
                       and (threshold == 0 or Strings.ascii_count(v) >= threshold)
                       and (offset := certificate_bytes.find(bytearray(v)
                                                             if isinstance(v, bytes)
                                                             else str(v).encode("UTF-8"))) >= -1
                ]

            except Exception as ex:
                Tools.print_error(ex)

            try:
                if cert_entry.certificate_type == MicrosoftPe.CertificateEntry.CertificateTypeEnum.pkcs_signed_data:
                    pkcs7 = CA.load_pkcs7(cert_entry.certificate_bytes)

                    certs: list[Certificate] = CA.get_pkcs7_certificates(pkcs7)

                    items2 = {
                        i: dict(offset=offset, x509=c, pub=pub, size=len(bytearray(pub)))
                        for i, c in enumerate(certs)
                        if (pub := c.public_bytes(serialization.Encoding.DER)) is not None
                           and (offset := certificate_bytes.find(bytearray(pub))) >= -1
                    }

                    for idx, cert_data in items2.items():
                        x509_cert = cert_data['x509']
                        b_data = certificate_bytes[cert_data['offset']: cert_data['offset'] + cert_data['size']]
                        s_lookup = []
                        s_lookup.append(str(cert_data['x509'].serial_number))
                        s_lookup.append(next((
                            s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                            in x509_cert.subject.rdns
                            if 'cn=' in s.rfc4514_string().lower()
                        ), x509_cert.subject.rfc4514_string()))
                        s_lookup += [s
                                     if '=' not in s else
                                     s.split('=', 2)[1].strip() if len(s.split('=')) > 1 else s
                                     for s in x509_cert.subject.rfc4514_string().split(',')
                                     if s.strip() != ''
                                     ]
                        s_lookup.append(next((
                            s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                            in x509_cert.issuer.rdns
                            if 'cn=' in s.rfc4514_string().lower()
                        ), x509_cert.issuer.rfc4514_string()))
                        s_lookup += [s
                                     if '=' not in s else
                                     s.split('=', 2)[1].strip() if len(s.split('=')) > 1 else s
                                     for s in x509_cert.issuer.rfc4514_string().split(',')
                                     if s.strip() != ''
                                     ]

                        subject_key = x509.SubjectKeyIdentifier.from_public_key(x509_cert.public_key())
                        s_lookup.append(''.join(chr(c) for c in subject_key.key_identifier))

                        authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(x509_cert.public_key())
                        s_lookup.append(''.join(chr(c) for c in authority_key.key_identifier))

                        try:
                            sha1_hash = cert_data['x509'].fingerprint(hashes.SHA1())
                            if sha1_hash is not None:
                                if isinstance(sha1_hash, bytes):
                                    sha1_hash = sha1_hash.decode("UTF-8")
                                    s_lookup.append(sha1_hash)
                        except:
                            pass

                        s_lookup += CA.get_ocsp_urls(x509_cert)

                        san = CA.get_certificate_san(x509_cert)

                        for idx2, s in enumerate(san):
                            s_lookup.append(s)

                        # Remove duplicated
                        s_lookup = set(s_lookup)

                        for s in [i for i in s_lookup if len(i) > string_min]:
                            yield from Strings.find_data_position(
                                data=s,
                                raw_base_address=cert_entry.pointer_to_raw_data + cert_data['offset'],
                                virtual_base_address=cert_entry.pointer_to_raw_data + cert_data['offset'],
                                section='security',
                                source_data=b_data,
                                flags=['cert']
                            )

            except Exception as ex:
                Tools.print_error(ex)

    @staticmethod
    def find_data_position(data: str, raw_base_address: int, virtual_base_address: int,
                           section: str, source_data: Union[bytes, bytearray],
                           is_dotnet_section: bool = False,
                           flags: list[str] = []):
        if isinstance(source_data, bytes):
            source_data = bytearray(source_data)
        for enc in StringsEncoding:
            b_data = StringPart.encode(data=data, encoding=enc)
            if b_data is not None and len(b_data) > 0:
                idx = -1
                while (idx := source_data.find(b_data, idx + 1)) != -1:
                    yield StringPart(data=b_data,
                                     address=raw_base_address + idx,
                                     virtual_address=virtual_base_address + idx,
                                     size=len(b_data),
                                     encoding=enc,
                                     section=section,
                                     is_dotnet_section=is_dotnet_section,
                                     flags=flags
                                     )
