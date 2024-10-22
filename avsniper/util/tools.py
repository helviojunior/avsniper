#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import base64
import datetime
import hashlib
import json
import os
import platform
import shutil
import string, random, sys, re
import struct
import unicodedata
from os.path import expanduser
from pathlib import Path
from typing import Union, Optional
import io

import hexdump
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.x509 import BasicConstraints

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.libs.ca import CA
import avsniper.libs.versioninfo.parser as vi

from avsniper.util.color import Color
from avsniper.util.microsoft_pe_holder import MicrosoftPeHolder

_texts = {
    'qty': 'Quantity',
    'company_similarity': 'Company Similarity'
}


class Tools:

    def __init__(self):
        pass

    @staticmethod
    def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for x in range(size))

    @staticmethod
    def clear_line(min_size=100):
        try:
            if sys.stderr.isatty():
                sys.stderr.write("\033[K")
                sys.stdout.write("\033[K")  # Clear to the end of line
                sys.stderr.write("\r\033[0m")

                try:
                    size = os.get_terminal_size(fd=os.STDOUT_FILENO)
                except:
                    size = min_size

                print((" " * size), end='\r', flush=True)
                print((" " * size), file=sys.stderr, end='\r', flush=True)
        except AttributeError:  # output does not support isatty()
            pass

    @staticmethod
    def permited_char_filename(s):
        if s.isalpha():
            return True
        elif bool(re.match("^[A-Za-z0-9]*$", s)):
            return True
        elif s == "-":
            return True
        elif s == "_":
            return True
        elif s == ".":
            return True
        else:
            return False

    @staticmethod
    def sanitize_filename(name):
        if name is None:
            return ''
        name = Tools.strip_accents(name.strip())
        while ('  ' in name):
            name = name.replace('  ', ' ')
        name = name.replace(' ', '-')
        while ('--' in name):
            name = name.replace('--', '-')
        return ''.join(filter(Tools.permited_char_filename, name))

    @staticmethod
    def permited_char(s):
        if s in ['\r', '\n', '\t', '\x0b', '\x0c']:
            return False
        elif s.isalpha():
            return True
        elif bool(re.match("^[A-Za-z0-9:]*$", s)):
            return True
        elif s == ".":
            return True
        elif s == ",":
            return True
        elif s in string.printable:
            return True
        else:
            return False

    @staticmethod
    def mandatory():
        Color.pl('{!} {R}error: missing a mandatory option, use -h help{W}\r\n')
        Tools.exit_gracefully(1)

    @staticmethod
    def exit_gracefully(code=0):
        exit(code)

    @staticmethod
    def count_file_lines(filename: str):
        def _count_generator(reader):
            b = reader(1024 * 1024)
            while b:
                yield b
                b = reader(1024 * 1024)

        with open(filename, 'rb') as fp:
            c_generator = _count_generator(fp.raw.read)
            # count each \n
            count = sum(buffer.count(b'\n') for buffer in c_generator)
            return count + 1

    @staticmethod
    def clear_string(text):
        return ''.join(filter(Tools.permited_char, Tools.strip_accents(text))).strip().lower()

    @staticmethod
    def strip_accents(text):
        try:
            text = unicode(text, 'utf-8')
        except NameError:  # unicode is a default on python 3
            pass

        text = unicodedata.normalize('NFD', text) \
            .encode('utf-8', 'ignore').decode("utf-8")

        return str(text).strip()

    @staticmethod
    def sizeof_fmt(num, suffix="B", start_unit=""):
        started = False
        for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
            if started or start_unit.upper() == unit:
                started = True
                if abs(num) < 1024.0:
                    return f"{num:3.1f} {unit}{suffix}"
                num /= 1024.0
        return f"{num:.1f} Y{suffix}"

    @staticmethod
    def get_dict_value(data: dict, key: str, default=None):
        if data is None:
            return default

        # if not isinstance(data, dict):
        #    return

        # Return if matches
        if key in data:
            return data.get(key, default)

        # Try to locate with the key in lowercase
        return next(
            iter([
                v for k, v in data.items()
                if k.strip().lower() == key
            ]), default)

    @staticmethod
    def json_serial(obj):
        """JSON serializer for objects not serializable by default json code"""

        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("UTF-8")

        raise TypeError("Type %s not serializable" % type(obj))

    @staticmethod
    def format_text_header(text) -> str:
        if text in _texts.keys():
            return _texts[text]

        return text.capitalize()

    @staticmethod
    def get_ansi_tabulated(data: list, tab: str) -> str:

        if len(data) == 0:
            return ''

        from tabulate import _table_formats, tabulate, TableFormat, Line, DataRow

        _table_formats["ccat"] = TableFormat(
            lineabove=Line(Color.s("{GR}%s" % tab), Color.s("{GR}─{W}"), Color.s("{GR}┬{W}"), ""),
            linebelowheader=Line(Color.s("{GR}%s" % tab), Color.s("{GR}─{W}"), Color.s("{GR}┼{W}"), ""),
            linebetweenrows=None,
            linebelow=Line(Color.s("{GR}%s" % tab), Color.s("{GR}─{W}"), Color.s("{GR}┴{W}"), ""),
            headerrow=DataRow(Color.s("{GR}%s{C}" % tab), Color.s("{GR}│{C}"), ""),
            datarow=DataRow(Color.s("{GR}%s{W}{O}{D}" % tab), Color.s("{W}{GR}│{W}"), ""),
            padding=1,
            with_header_hide=None,
        )

        headers = [(Tools.format_text_header(h) if len(h) > 2 and h[0:2] != '__' else ' ') for h in data[0].keys()]
        data = [item.values() for item in data]

        # Available only at v0.9.0 and upper
        cols = {}
        try:
            from tabulate.version import __version_tuple__ as tabv
            if tabv[0] > 0 and tabv[1] >= 9:
                cols = dict(
                    maxcolwidths=[None, 200]
                )
        except:
            pass
        tmp_data = tabulate(data, headers, tablefmt='ccat')

        return tmp_data

    @staticmethod
    def print_error(error: Exception, force: bool = False):
        from avsniper.config import Configuration
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(error))

        if Configuration.verbose >= 2 or force:
            Color.pl('\n{!} {O}Full stack trace below')
            from traceback import format_exc
            Color.p('\n{!}    ')
            err = format_exc().strip()
            err = err.replace('\n', '\n{W}{!} {W}   ')
            err = err.replace('  File', '{W}{D}File')
            err = err.replace('  Exception: ', '{R}Exception: {O}')
            Color.pl(err + '{W}')

    @staticmethod
    def escape_ansi(text):
        if text is None:
            return ''

        pattern = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
        return pattern.sub('', text)

    @staticmethod
    def ljust(text, size):
        s_text = Tools.escape_ansi(Color.s(text))
        return text + (' ' * (size - len(s_text)))

    @staticmethod
    def int_to_hex(value: int, fmt: Union[bytes, str] = '>I') -> str:
        return "0x" + (''.join([f'{x:02x}' for x in struct.pack(fmt, value)]))

    @staticmethod
    def hexdump(data: Union[bytes, str, bytearray],
                start_address: int = 0,
                highlight_address: int = None,
                highlight_size: int = 0,
                prefix: str = '') -> str:

        if highlight_address is not None and start_address > 0 and highlight_address > 0 and \
                (highlight_address - start_address) % 16 > 0:
            cut = (16 - ((highlight_address - start_address) % 16))
            data = data[cut:]
            start_address += cut

        dump_table = {
            (start_address + (idx * 16)): dict(
                hex=h1 + (['  '] * (16 - len(h1))),
                ascii=v.ljust(76, ' ')[-16:],
            )
            for idx, v in enumerate(hexdump.hexdump(data, result='generator'))
            if (h1 := [
                x for x in
                (' '.join(v.split(':')[1:]).lstrip(' ')[:-16].strip().strip('\t')).split(' ')
                if x.strip() != ''
            ]) is not None
        }

        if highlight_address is None:
            highlight_address = -1

        dump = prefix + f'\n{prefix}'.join([
            (('{O}  → %s:{GR} ' if ln_addr == highlight_address else
              (
                  '{O}    %s:{GR} '
                  if highlight_address < ln_addr < highlight_address + highlight_size else '    {GR}%s: ')
              ) % (
                 ''.join([f'{x:02x}' for x in struct.pack('>I', ln_addr)])
             ).zfill(8)) +
            ' '.join([
                ('{R}%s{GR}' if highlight_address <= ln_addr + idx < highlight_address + highlight_size else '%s') %
                (x + (' ' if idx == 7 else ''))
                for idx, x in
                enumerate(data['hex'])
            ]) +
            '  ' + ''.join([
                ('{C}%s{GR}' if highlight_address <= ln_addr + idx < highlight_address + highlight_size else '%s') %
                x for idx, x in
                enumerate(data['ascii'])
            ]).ljust(16, ' ')
            for ln_addr, data in dump_table.items()
        ])

        return dump

    @staticmethod
    def pe_certificate(data: Union[bytes, str, MicrosoftPe],
                       colored: bool = True, highlight_address: int = None,
                       highlight_data: Union[bytes, bytearray] = None,
                       show_only_highlighted: bool = False) -> str:

        from avsniper.config import Configuration

        res_txt = ""

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        color1 = "{O}"
        color2 = "\033[92m"
        color3 = "{C}"
        color4 = "\033[35m"

        if show_only_highlighted and (highlight_address is None or highlight_address == 0):
            show_only_highlighted = False

        if pe_file.pe.certificate_table is not None:

            res_path = str(Path(os.path.join(Configuration.path, '../certificates')).resolve())
            shutil.rmtree(res_path, ignore_errors=True)
            if not os.path.isdir(res_path):
                os.mkdir(res_path)

            if show_only_highlighted:
                items1 = [
                    c for c in pe_file.pe.certificate_table.items
                    if c.pointer_to_raw_data <= highlight_address <= (
                            c.pointer_to_raw_data + c.length)
                ]
            else:
                items1 = pe_file.pe.certificate_table.items

            for idx, cert_entry in enumerate(items1):
                res_last = idx == len(items1) - 1
                res_prefix = '    ' if res_last else '│   '
                res_txt += "{GR}"
                res_txt += '│   \n' if idx > 0 else ''
                res_txt += '└── ' if res_last else '├── '

                h = (highlight_address is not None
                     and cert_entry.pointer_to_raw_data <= highlight_address <= (
                             cert_entry.pointer_to_raw_data + cert_entry.length))

                res_txt += ("{R}" if h else color3) + ("Certificate Entry{GR}, "
                                                       "Type: %s{GR}, "
                                                       "Raw. Address: %s{GR}, "
                                                       "Size: %s%s{GR}\n") % (
                               color1 + cert_entry.certificate_type.name.capitalize(),
                               color1 + '0x' + (''.join([
                                   f'{x:02x}' for x in struct.pack('>I', cert_entry.pointer_to_raw_data)
                               ])).zfill(8),
                               color1 + '0x' + (''.join([
                                   f'{x:02x}' for x in struct.pack('>I', cert_entry.length)
                               ])).zfill(8),
                               "{O}  ← " if h else ""
                           )

                certificate_bytes = bytearray(cert_entry.certificate_bytes)

                sha256_hash = hashlib.sha256(cert_entry.certificate_bytes).hexdigest().lower()
                res_txt += res_prefix + "├── {GR}SHA-256..: {O}%s{GR}\n" % sha256_hash

                try:
                    mime = Tools.get_mimes(cert_entry.certificate_bytes)
                    res_txt += res_prefix + "├── {GR}MIME.....: {O}%s{GR}\n" % mime
                except Exception as ex:
                    if Configuration.verbose >= 2:
                        Tools.print_error(ex)

                try:
                    attrs = CA.get_pkcs7_human_data(certificate_bytes)

                    info_prefix = res_prefix + "│   "
                    res_txt += "{GR}"
                    res_txt += res_prefix + '├── '
                    res_txt += color2 + "Sign Info{GR}, entries: %s\n" % (
                        len(attrs) if attrs is not None else 0)

                    items2 = {
                        i: dict(
                            addr=addr,
                            title=k,
                            value=v if isinstance(v, dict) else ('{GR}\n' + Tools.hexdump(
                                data=v,
                                start_address=addr,
                                highlight_address=highlight_address,
                                highlight_size=len(highlight_data) if highlight_data is not None else 0,
                                prefix=info_prefix + ("│ " if i < len(attrs) - 1 else "  ")
                            ) if isinstance(v, bytes) else str(v)),
                            highlight=h) for i, k in enumerate(attrs)
                        if (v := attrs[k]) is not None
                           and (f_idx := certificate_bytes.find(bytearray(v)
                                                                if isinstance(v, bytes)
                                                                else str(v).encode("UTF-8"))) >= -1
                           and (addr := cert_entry.pointer_to_raw_data + f_idx) >= -1
                           and ((h := (addr <= highlight_address <= addr + len(v))) or True)
                           and (not isinstance(v, bytes) or h or not show_only_highlighted)
                    }
                    last_idx = max(items2.keys()) if len(items2) > 0 else 0

                    for idx1, attr_data in items2.items():
                        res_txt += info_prefix + ('└── ' if idx1 == last_idx else '├── ')
                        if isinstance(attr_data['value'], dict):

                            for idx2, att in enumerate(attr_data['value'].keys()):
                                res_txt += "%s (%s){GR}{GR}\n" % (
                                    color3 + attr_data['title'],
                                    att)

                                items3 = {
                                    i: dict(
                                        addr=addr,
                                        title=k,
                                        value='{GR}\n' + Tools.hexdump(
                                            data=v,
                                            start_address=addr,
                                            highlight_address=highlight_address,
                                            highlight_size=len(highlight_data) if highlight_data is not None else 0,
                                            prefix=info_prefix + (
                                                "    │ " if i < len(attr_data['value'][att]) - 1 else "      ")
                                        ) if isinstance(v, bytes) else str(v),
                                        highlight=h) for i, k in enumerate(attr_data['value'][att].keys())
                                    if (v := attr_data['value'][att][k]) is not None
                                       and (f_idx := certificate_bytes.find(bytearray(v)
                                                                            if isinstance(v, bytes)
                                                                            else str(v).encode("UTF-8"))) >= -1
                                       and (addr := cert_entry.pointer_to_raw_data + f_idx) >= -1
                                       and ((h := (addr <= highlight_address <= addr + len(v))) or True)
                                       and (not isinstance(v, bytes) or h or not show_only_highlighted)
                                }
                                attr_last_idx = max(items3.keys()) if len(items3) > 0 else 0

                                for idx2, attr_data2 in items3.items():
                                    res_txt += info_prefix + '    ' + ('└── ' if idx2 == attr_last_idx else '├── ')

                                    res_txt += "%s{GR}: %s%s{GR}\n" % (
                                        color3 + attr_data2['title'],
                                        color1 + attr_data2['value'],
                                        "{O}  ← " if attr_data2['highlight'] else "")

                        else:
                            res_txt += "%s{GR}: %s%s{GR}\n" % (
                                color3 + attr_data['title'],
                                color1 + attr_data['value'],
                                "{O}  ← " if attr_data['highlight'] else "")

                except Exception as ex:
                    if Configuration.verbose >= 2:
                        Tools.print_error(ex)

                try:
                    if cert_entry.certificate_type == MicrosoftPe.CertificateEntry.CertificateTypeEnum.pkcs_signed_data:
                        pkcs7 = CA.load_pkcs7(cert_entry.certificate_bytes)

                        f_name = os.path.join(res_path, f'{sha256_hash}.p7s')

                        with open(f_name, 'wb') as f_res:
                            f_res.write(cert_entry.certificate_bytes)

                        certs = CA.get_pkcs7_certificates(pkcs7)

                        res_txt += "{GR}"
                        res_txt += res_prefix + "└── "
                        res_txt += color2 + "X509 Certificates{GR}, entries: %s\n" % (
                            len(certs) if certs is not None else 0)

                        items2 = {
                            i: dict(pub_addr=pub_addr, x509=c, pub=pub, highlight=h) for i, c in enumerate(certs)
                            if (pub := c.public_bytes(serialization.Encoding.DER)) is not None
                               and (f_idx := certificate_bytes.find(bytearray(pub))) >= -1
                               and (pub_addr := cert_entry.pointer_to_raw_data + f_idx) >= -1
                               and ((h := (pub_addr <= highlight_address <= pub_addr + len(pub))) or True
                                    )
                        }
                        last_idx = max(items2.keys()) if len(items2) > 0 else 0

                        for idx1, cert_data in items2.items():

                            res_txt += "{GR}"
                            res_txt += res_prefix
                            cert_last = idx1 == last_idx
                            cert_prefix = f'{res_prefix}     ' if cert_last else f'{res_prefix}    │'
                            res_txt += '    └── ' if cert_last else '    ├── '

                            res_txt += color3 + ("X509 Entry %s{GR}, "
                                                 "Address: %s{GR} "
                                                 "Size: %s%s{GR}\n") % (
                                           idx1,
                                           color1 + '0x' + (''.join([
                                               f'{x:02x}' for x in struct.pack('>I', cert_data['pub_addr'])
                                           ])).zfill(8),
                                           color1 + '0x' + (''.join([
                                               f'{x:02x}' for x in struct.pack('>I', len(cert_data['pub']))
                                           ])).zfill(8),
                                           "{O}  ← " if cert_data['highlight'] else "")

                            res_txt += (cert_prefix + "   ├── {GR}Serial......: {O}%s{GR}\n" %
                                        cert_data['x509'].serial_number)
                            res_txt += (cert_prefix + "   ├── {GR}Subject.....: {O}%s{GR}\n" %
                                        next((
                                            s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                                            in cert_data['x509'].subject.rdns
                                            if 'cn=' in s.rfc4514_string().lower()
                                        ), cert_data['x509'].subject.rfc4514_string()))
                            res_txt += (cert_prefix + "   ├── {GR}Issuer......: {O}%s{GR}\n" %
                                        next((
                                            s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                                            in cert_data['x509'].issuer.rdns
                                            if 'cn=' in s.rfc4514_string().lower()
                                        ), cert_data['x509'].issuer.rfc4514_string()))
                            res_txt += (cert_prefix + "   ├── {GR}Fingerprint.: {O}%s{GR}\n" %
                                        (''.join([
                                            f'{x:02x}' for x in cert_data['x509'].fingerprint(hashes.SHA1())
                                        ]))
                                        )

                            san = CA.get_certificate_san(cert_data['x509'])
                            res_txt += (cert_prefix + "   └── " + color4 + "Alternate names{GR}, entries %s{GR}\n" %
                                        len(san))

                            for idx2, s in enumerate(san):
                                res_txt += cert_prefix + \
                                           ('        └── ' if idx2 == len(san) - 1 else '        ├── ') + \
                                           color4 + \
                                           "Alternate name %s{GR}: %s{GR}\n" % (idx2, s)

                            # Save the Cert
                            f_name = os.path.join(res_path, f'{cert_data["x509"].serial_number}.cer')
                            with open(f_name, 'wb') as f_res:
                                f_res.write(cert_data['pub'])

                except Exception as ex:
                    if Configuration.verbose >= 2:
                        Tools.print_error(ex)

                if highlight_data is not None:
                    hex = ''.join([f'{x:02x}' for x in highlight_data])
                    res_txt = res_txt.replace(hex.lower(), '{R}' + hex.lower() + 'GR')
                    res_txt = res_txt.replace(hex.upper(), '{R}' + hex.upper() + 'GR')

                # res_txt += ("└── {GR}Entropy......: {O}fds{GR}\n")

        if res_txt != '':
            res_txt = "{B}Digital Signature{GR}\n" + res_txt

        if not colored:
            Tools.escape_ansi(res_txt)

        return Color.s(res_txt)

    @staticmethod
    def pe_certificate_list(data: Union[bytes, str, MicrosoftPe]) -> list:

        from avsniper.config import Configuration

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.certificate_table is None:
            return []

        for idx, cert_entry in enumerate(pe_file.pe.certificate_table.items):
            try:
                if cert_entry.certificate_type == MicrosoftPe.CertificateEntry.CertificateTypeEnum.pkcs_signed_data:
                    pkcs7 = CA.load_pkcs7(cert_entry.certificate_bytes)
                    certs = CA.get_pkcs7_certificates(pkcs7)

                    for x509 in certs:
                        san = CA.get_certificate_san(x509)
                        yield dict(
                            serial_number=x509.serial_number,
                            subject=next((
                                s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                                in x509.subject.rdns
                                if 'cn=' in s.rfc4514_string().lower()
                            ), x509.subject.rfc4514_string()),
                            issuer=next((
                                s.rfc4514_string().replace('CN=', '').replace('cn=', '') for s
                                in x509.issuer.rdns
                                if 'cn=' in s.rfc4514_string().lower()
                            ), x509.issuer.rfc4514_string()),
                            fingerprint=''.join([
                                f'{x:02x}' for x in x509.fingerprint(hashes.SHA1())
                            ]),
                            san=[str(s).strip() for s in san] if san is not None else [],
                            x509=x509
                        )

            except Exception as ex:
                if Configuration.verbose >= 2:
                    Tools.print_error(ex)

    @staticmethod
    def pe_create_fake_cert_pkcs12(data: Union[bytes, str, MicrosoftPe], filename: str = None) -> bytes:

        cert_list = {
            x509.subject.rfc4514_string(): x509
            for c in Tools.pe_certificate_list(data)
            if (x509 := c['x509']) is not None
        }

        cert_tree1 = {
            idx + 1: (
                subject,
                x509.issuer.rfc4514_string(),
                next(iter([
                    True
                    for e in x509.extensions
                    if e.oid == ObjectIdentifier("2.5.29.19")  # basicConstraints
                       and (v := e.value) is not None
                       and isinstance(v, BasicConstraints)
                       and v.ca
                ]), False)
            )
            for idx, (subject, x509) in enumerate(cert_list.items())
        }
        cert_tree2 = {
            idx: dict(
                subject=subject,
                issuer=issuer,
                is_ca=is_ca,
                parent=next(iter([
                    i
                    for i, (s, _, _) in cert_tree1.items()
                    if s == issuer
                ]), 0)
            )
            for idx, (subject, issuer, is_ca) in cert_tree1.items()
        }

        # Create a full ordered list
        cert_tree = sorted(
            {
                **cert_tree2,
                **{
                    0: dict(
                        subject=entry['issuer'],
                        issuer=entry['issuer'],
                        is_ca=entry['is_ca'],
                        parent=0
                    )
                    for idx, entry in cert_tree2.items()
                    if entry['parent'] == 0
                }
            }.items()
            , key=lambda x: f"{x[1]['parent']:03}{x[0]:03}", reverse=False)

        fake_certs = {}

        for idx, entry in cert_tree:
            subject = CA.parse_dn(entry['subject'])
            if idx == 0:  # CA Root
                ca = CA()
                ca.create_ca_from_name(subject)
                fake_certs = {**fake_certs, **{entry['subject']: dict(
                    x509=ca.ca_cert, is_ca=entry['is_ca'], json=ca.get_json())}}
            else:
                ca = CA()
                ca.load_json(fake_certs[entry['issuer']]['json'])
                x509 = cert_list[entry['subject']]
                if x509 is None:
                    raise Exception(f"X509 Certificate '{entry['issuer']}' not found")
                if entry['is_ca']:
                    new_ca = ca.create_intermediate_ca(subject)
                    fake_certs = {**fake_certs, **{entry['subject']: dict(
                        x509=new_ca.ca_cert, is_ca=entry['is_ca'], json=new_ca.get_json())}}
                else:
                    new_cert, new_key = ca.create_signed_cert(
                        name=subject,
                        key_usage=crypto.X509Extension(b"keyUsage", True, b"digitalSignature"),
                        extended_key_usage=crypto.X509Extension(b"extendedKeyUsage", True, b"codeSigning"),
                        subject_alternative_name=next(iter([
                            ','.join([
                                f"{t}:{v}"
                                for t, v in CA.get_certificate_san2(x509)
                            ])
                        ]), None)
                    )

                    fake_certs = {**fake_certs, **{entry['subject']: dict(
                        x509=crypto.load_certificate(crypto.FILETYPE_PEM, new_cert),
                        is_ca=entry['is_ca'], key=new_key)}}

        cert = next(iter([
            (c['x509'], key)
            for s, c in fake_certs.items()
            if not c['is_ca']
               and (strkey := c.get('key', None)) is not None
               and (key := crypto.load_privatekey(crypto.FILETYPE_PEM, strkey))
        ]), None)

        if cert is None:
            raise Exception(f"New X509 Certificate not found")

        ca_certificates = [
            c['x509']
            for s, c in fake_certs.items()
            if c['is_ca']
        ]

        if ca_certificates is None or len(ca_certificates) == 0:
            raise Exception(f"New X509 CA Certificates not found")

        pkcs12 = CA.generate_pkcs12(
            passphrase="123456",
            cert=cert[0],
            key=cert[1],
            ca_certificates=ca_certificates
        )

        if filename is not None:
            with open(filename, 'wb') as p12:
                p12.write(pkcs12)

        return pkcs12

    @staticmethod
    def pe_resource_table(data: Union[bytes, str, MicrosoftPe],
                          colored: bool = True, highlight_address: int = None,
                          show_only_highlighted: bool = False) -> str:

        from avsniper.config import Configuration

        res_txt = ""

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        color1 = "{O}"
        color2 = "\033[35m"
        color3 = "{C}"
        color4 = "\033[92m"

        if show_only_highlighted and (highlight_address is None or highlight_address == 0):
            show_only_highlighted = False

        if pe_file.pe.resources_table is not None:

            if show_only_highlighted:
                items1 = [
                    i for i in pe_file.pe.resources_table.items
                    if i.is_directory and i.directory_table is not None
                       and next(iter([
                        i1 for i1 in i.directory_table.items
                        if i1.is_directory and i1.directory_table is not None
                           and next(iter([
                            i2 for i2 in i1.directory_table.items
                            if highlight_address is not None
                               and i2.pointer_to_raw_data <= highlight_address <= (
                                       i2.pointer_to_raw_data + i2.data_size)
                        ]), None) is not None
                    ]), None) is not None
                ]
            else:
                items1 = pe_file.pe.resources_table.items

            if len(items1) > 0:
                res_txt += color2 + "Resource Directory{GR}, Named entries: %s, ID entries: %s{GR}\n" % (
                    pe_file.pe.resources_table.number_of_named_entries,
                    pe_file.pe.resources_table.number_of_id_entries)

            for idx, res in enumerate(items1):
                res_last = idx == len(items1) - 1
                res_prefix = '    ' if res_last else '│   '
                res_txt += "{GR}"
                res_txt += '│   \n' if idx > 0 else ''
                res_txt += '└── ' if res_last else '├── '
                res_txt += color3 + "Resource Directory Entry %s{GR}, %s: %s, Type: %s{GR}\n" % (
                    idx,
                    "Name" if res.is_name_string else 'ID',
                    res.name_string if res.is_name_string else res.name_address,
                    color1 + res.name_type.name.capitalize())
                if res.is_directory and res.directory_table is not None:
                    res_txt += "{GR}"
                    res_txt += res_prefix + "└── "
                    res_txt += color2 + "Resource Directory{GR}, Named entries: %s, ID entries: %s\n" % (
                        res.directory_table.number_of_named_entries,
                        res.directory_table.number_of_id_entries)

                    if show_only_highlighted:
                        items2 = [

                            i1 for i1 in res.directory_table.items
                            if i1.is_directory and i1.directory_table is not None
                               and next(iter([
                                i2 for i2 in i1.directory_table.items
                                if highlight_address is not None
                                   and i2.pointer_to_raw_data <= highlight_address <= (
                                           i2.pointer_to_raw_data + i2.data_size)
                            ]), None) is not None
                        ]
                    else:
                        items2 = res.directory_table.items

                    for idx1, res1 in enumerate(items2):
                        res_txt += "{GR}"
                        res_txt += res_prefix
                        res1_last = idx1 == len(items2) - 1
                        res1_prefix = f'{res_prefix}     ' if res1_last else f'{res_prefix}    │'
                        res_txt += '    └── ' if res1_last else '    ├── '

                        res_txt += color3 + "Resource Directory Entry %s{GR}, %s: %s{GR}\n" % (
                            idx,
                            "Name" if res1.is_name_string else 'ID',
                            res1.name_string if res1.is_name_string else res1.name_address)

                        if res1.is_directory and res1.directory_table is not None:
                            res_txt += "{GR}"
                            res_txt += res1_prefix + "   └── "
                            res_txt += color2 + "Resource Directory{GR}, Named entries: %s, ID entries: %s\n" % (
                                res1.directory_table.number_of_named_entries,
                                res1.directory_table.number_of_id_entries)

                            if show_only_highlighted:
                                items3 = [

                                    i2 for i2 in res1.directory_table.items
                                    if highlight_address is not None
                                       and i2.pointer_to_raw_data <= highlight_address <= (
                                               i2.pointer_to_raw_data + i2.data_size)

                                ]
                            else:
                                items3 = res1.directory_table.items

                            for idx2, res2 in enumerate(items3):
                                res_txt += "{GR}"
                                res2_prefix = res1_prefix + '           '
                                res_txt += res1_prefix
                                res2_last = idx2 == len(items3) - 1
                                res_txt += '       └── ' if res2_last else '       ├── '

                                h = (highlight_address is not None
                                     and res2.pointer_to_raw_data <= highlight_address <= (
                                             res2.pointer_to_raw_data + res2.data_size))

                                res_txt += ("{R}" if h else color4) + ("Resource Data Entry %s{GR}, %s: %s, "
                                                                       "Virt. Address: %s{GR}, "
                                                                       "Raw. Address: %s{GR}, "
                                                                       "Size: %s%s{GR}\n") % (
                                               idx,
                                               "Name" if res2.is_name_string else 'ID',
                                               res2.name_string if res2.is_name_string else res2.name_address,
                                               color1 + "0x" + (
                                                   ''.join(
                                                       [f'{x:02x}' for x in struct.pack('>I', res2.virtual_address)])
                                               ).zfill(8),
                                               color1 + "0x" + (
                                                   ''.join([f'{x:02x}' for x in
                                                            struct.pack('>I', res2.pointer_to_raw_data)])
                                               ).zfill(8),
                                               color1 + "0x" + (
                                                   ''.join([f'{x:02x}' for x in struct.pack('>I', res2.data_size)])
                                               ).zfill(8),
                                               "{O}  ← " if h else ""
                                           )

                                if res.name_type == MicrosoftPe.DirectoryEntryType.icon:
                                    try:
                                        icon = Tools.pe_get_icon_entry(pe_file, res2)
                                        sha256_hash = hashlib.sha256(icon).hexdigest().lower()

                                        res_txt += res2_prefix + ("├── {GR}Icon SHA-256.: %s{GR}\n" % sha256_hash)
                                        try:
                                            mime = Tools.get_mimes(icon)
                                            res_txt += res2_prefix + ("├── {GR}Icon MIME....: %s{GR}\n" % mime)
                                        except Exception as ex:
                                            if Configuration.verbose >= 2:
                                                Tools.print_error(ex)
                                    except Exception as e:
                                        if Configuration.verbose >= 2:
                                            Tools.print_error(e)

                                if not isinstance(res2.data, MicrosoftPe.IconGroup):
                                    try:
                                        sha256_hash = hashlib.sha256(res2.data.data).hexdigest().lower()
                                        entropy = Tools.get_entropy(res2.data.data)

                                        res_txt += res2_prefix + ("├── {GR}Raw SHA-256..: {O}%s{GR}\n" % sha256_hash)
                                        try:
                                            mime = Tools.get_mimes(res2.data.data)
                                            res_txt += res2_prefix + ("├── {GR}Raw MIME.....: {O}%s{GR}\n" % mime)
                                        except Exception as ex:
                                            if Configuration.verbose >= 2:
                                                Tools.print_error(ex)
                                        res_txt += res2_prefix + ("└── {GR}Entropy......: {O}%s{GR}\n" % entropy)
                                    except Exception as e:
                                        if Configuration.verbose >= 2:
                                            Tools.print_error(e)

                        if not res1_last:
                            res_txt += res1_prefix + '\n'

        if not colored:
            Tools.escape_ansi(res_txt)

        return Color.s(res_txt)

    @staticmethod
    def pe_get_icon_entry(data: Union[bytes, str, MicrosoftPe],
                          icon_data: MicrosoftPe.ResourceDirectoryEntry = None) -> Optional[bytearray]:

        from avsniper.config import Configuration

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.resources_table is None:
            return None

        icons = {}

        for idx, res in enumerate(pe_file.pe.resources_table.items):
            if res.is_directory and res.directory_table is not None:
                for idx1, res1 in enumerate(res.directory_table.items):
                    if res1.is_directory and res1.directory_table is not None:
                        for idx2, res2 in enumerate(res1.directory_table.items):
                            if res2 == icon_data and res.name_type == MicrosoftPe.DirectoryEntryType.icon:
                                icons[res1.name_address] = res2

        if len(icons) == 0:
            return None

        for idx, res in enumerate(pe_file.pe.resources_table.items):
            if res.is_directory and res.directory_table is not None and \
                    res.name_type in (MicrosoftPe.DirectoryEntryType.group_cursor2,
                                      MicrosoftPe.DirectoryEntryType.group_cursor4):
                for idx1, res1 in enumerate(res.directory_table.items):
                    if res1.is_directory and res1.directory_table is not None:
                        for idx2, res2 in enumerate(res1.directory_table.items):

                            try:
                                if isinstance(res2.data, MicrosoftPe.IconGroup):
                                    for ico in res2.data.items:
                                        if (ref_res := icons.get(ico.ordinal_id, None)) is not None:
                                            data = bytearray([0x00, 0x00])
                                            data += bytearray(struct.pack('<h', res2.data.image_type.value))
                                            data += bytearray([0x01, 0x00,
                                                               ico.width & 0xff,
                                                               ico.height & 0xff,
                                                               ico.icon_colors & 0xff,
                                                               0x00])
                                            data += bytearray(struct.pack('<h', int(ico.color_planes)))
                                            data += bytearray(struct.pack('<h', int(ico.bits_per_pixel)))
                                            data += bytearray(struct.pack('<i', int(ico.byte_size)))
                                            data += bytearray([0x16, 0x00, 0x00, 0x00])
                                            data += bytearray(ref_res.data.data)

                                            return data

                            except Exception as e:
                                if Configuration.verbose >= 2:
                                    Tools.print_error(e)

        return None

    @staticmethod
    def pe_resource_table_extract(file_id: int, data: Union[bytes, str, MicrosoftPe], save_address: int = None):

        from avsniper.config import Configuration

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.resources_table is not None:

            res_path = str(Path(os.path.join(Configuration.path, '../resources')).resolve())
            shutil.rmtree(res_path, ignore_errors=True)
            if not os.path.isdir(res_path):
                os.mkdir(res_path)

            for idx, res in enumerate(pe_file.pe.resources_table.items):
                if res.is_directory and res.directory_table is not None:
                    for idx1, res1 in enumerate(res.directory_table.items):
                        if res1.is_directory and res1.directory_table is not None:
                            for idx2, res2 in enumerate(res1.directory_table.items):
                                if save_address is not None \
                                        and res2.pointer_to_raw_data <= save_address <= (
                                        res2.pointer_to_raw_data + res2.data_size):

                                    n1 = str(res2.name_string if res2.is_name_string else res2.name_address)

                                    try:

                                        sha256_hash = hashlib.sha256(res2.data.data).hexdigest().lower()
                                        f_name = os.path.join(res_path,
                                                              (f'{file_id:03d}_{n1}_{sha256_hash}'
                                                               f'.{Tools.get_extension(res2.data.data)}'))

                                        with open(f_name, 'wb') as f_res:
                                            f_res.write(res2.data.data)

                                    except Exception as e:
                                        if Configuration.verbose >= 2:
                                            Tools.print_error(e)

                                    try:

                                        if res.name_type == MicrosoftPe.DirectoryEntryType.icon:
                                            icon = Tools.pe_get_icon_entry(pe_file, res2)
                                            sha256_hash = hashlib.sha256(icon).hexdigest().lower()
                                            f_name = os.path.join(res_path,
                                                                  (f'{file_id:03d}_{n1}_{sha256_hash}'
                                                                   f'.{Tools.get_extension(icon)}'))

                                            with open(f_name, 'wb') as f_res:
                                                f_res.write(icon)

                                    except Exception as e:
                                        if Configuration.verbose >= 2:
                                            Tools.print_error(e)

    @staticmethod
    def pe_file_tags(data: Union[bytes, str, MicrosoftPe]) -> str:

        tags = []

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                return 'raw data'

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # if pe_file.pe_header.coff_hdr.
        tags.append('PE')

        if pe_file.pe.optional_hdr.std.format.value == 0x107:
            tags.append('rom')
        elif pe_file.pe.optional_hdr.std.format.value == 0x10b:
            tags.append('x86')
            tags.append('Win 32')
        elif pe_file.pe.optional_hdr.std.format.value == 0x20b:
            tags.append('AMD64')
            tags.append('Win 64')

        if pe_file.pe.optional_hdr.windows.subsystem == MicrosoftPe.OptionalHeaderWindows.SubsystemEnum.native:
            tags.append('Native')
        elif pe_file.pe.optional_hdr.windows.subsystem == MicrosoftPe.OptionalHeaderWindows.SubsystemEnum.windows_gui:
            tags.append('Windows GUI')
        elif pe_file.pe.optional_hdr.windows.subsystem == MicrosoftPe.OptionalHeaderWindows.SubsystemEnum.windows_cui:
            tags.append('Windows Console')
        else:
            tags.append(pe_file.pe.optional_hdr.windows.subsystem.name.capitalize())

        if (
                pe_file.pe.optional_hdr.data_dirs.clr_runtime_header is not None
                and pe_file.pe.optional_hdr.data_dirs.clr_runtime_header.size >= 0x48
                and pe_file.pe.dotnet_header is not None
                and pe_file.pe.dotnet_metadata_header is not None
                and pe_file.pe.dotnet_metadata_header.streams is not None
                and len(pe_file.pe.dotnet_metadata_header.streams) > 0
        ):
            tags.append(f'.Net {pe_file.pe.dotnet_metadata_header.version_string}')

        ver = Tools.pe_version(pe_file)
        if ver is not None and isinstance(ver, dict):
            tags += [
                t for t in [
                    ver.get('InternalName', None),
                    ver.get('ProductName', None),
                    ver.get('ProductVersion', None),
                ]
                if t is not None and t.strip() != ''
            ]

        return ', '.join(tags)

    @staticmethod
    def to_datetime(epoch: [int, float]) -> datetime.datetime:
        return datetime.datetime(1970, 1, 1, 0, 0, 0) + datetime.timedelta(seconds=epoch)

    @staticmethod
    def to_boolean(text: [str, bool]) -> bool:
        return bool(text)

    @staticmethod
    def get_mime(file_path: str) -> str:
        return Tools.get_mimes(open(file_path, "rb").read(2048))

    @staticmethod
    def get_mimes(data: Union[str, bytes, bytearray]) -> str:
        import magic

        if isinstance(data, str):
            data = data.encode('utf-8', 'ignore')

        # Convert to <class 'bytes'>
        data = b"" + data

        if len(data) > 2048:
            data = data[:2048]

        f = magic.Magic(mime=True)

        try:
            return f.from_buffer(data).lower()
        except Exception as e:
            Tools.print_error(e)
            return 'application/octet-stream'

    @staticmethod
    def get_extension(data: Union[str, bytes, bytearray]) -> str:
        mime = Tools.get_mimes(data)
        from avsniper.config import Configuration
        try:
            with open(os.path.join(Configuration.lib_path, 'mime_ext.json'), 'rb') as pe:
                j_data = json.loads(pe.read().decode("UTF-8", "ignore"))

            return next((
                str(e.lower()) for e, v in j_data.items()
                if v.lower() == mime.lower()
            ), 'bin')

        except:
            return 'bin'

    @staticmethod
    def get_entropy(data: [str, bytes]) -> float:
        # https://en.wiktionary.org/wiki/Shannon_entropy
        from math import log2

        if isinstance(data, str):
            data = data.encode('utf-8', 'ignore')

        if len(data) == 0:
            return 0.0

        counters = {byte: 0 for byte in range(2 ** 8)}  # start all counters with zeros

        for byte in data:
            counters[byte] += 1

        probabilities = [counter / len(data) for counter in counters.values()]  # calculate probabilities for each byte

        entropy = -sum(
            probability * log2(probability) for probability in probabilities if probability > 0)  # final sum

        return round(entropy, 2)

    @staticmethod
    def try_or(fn, default, **kwargs):
        try:
            return fn(**kwargs)
        except:
            return default

    @staticmethod
    def kill_all_running():
        try:
            from avsniper.config import Configuration
            from avsniper.util.logger import Logger

            if Configuration.path is None:
                return

            pid = os.getpid()
            import psutil
            for proc in [
                p for p in
                psutil.process_iter()
                if int(p.pid) != int(pid)
                   and (tmp := Tools.try_or(p.cmdline, None)) is not None
                   and isinstance(tmp, list) and len(tmp) > 0
                   and (cmdline := tmp[0]) is not None
                   and Configuration.path in str(cmdline)
            ]:
                try:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Killing process ID {O}%s{GR}: {O}%s{W}' % (proc.pid, proc.name()))
                    proc.kill()
                except Exception as e:
                    pass
        except:
            pass

    @staticmethod
    def pe_overlay_data(data: Union[bytes, bytearray, MicrosoftPe]) -> dict:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        last_section = sorted(pe_file.pe.sections, key=lambda s: s.virtual_address, reverse=True)[0]
        pe_size = last_section.pointer_to_raw_data + last_section.size_of_raw_data

        return dict(
            has_ovarlay=len(data_bytes) > pe_size,
            start_addr=pe_size,
            end_addr=len(data_bytes),
            size=len(data_bytes) - pe_size,
        )

    @staticmethod
    def pe_strip_extradata(data: Union[bytes, bytearray, MicrosoftPe], error_on_equal: bool = True) -> Optional[
        bytearray]:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        last_section = sorted(pe_file.pe.sections, key=lambda s: s.virtual_address, reverse=True)[0]
        pe_size = last_section.pointer_to_raw_data + last_section.size_of_raw_data

        if pe_size == len(data_bytes) and error_on_equal:
            # return data_bytes
            raise Exception('This file has no additional data after PE structure')

        return data_bytes[0:pe_size]

    @staticmethod
    def pe_strip_certificate(data: Union[bytes, bytearray, MicrosoftPe], error_on_equal: bool = True) -> Optional[
        bytearray]:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        if pe_file.pe.optional_hdr.data_dirs.certificate_table.size == 0 and error_on_equal:
            # return data_bytes
            raise Exception('This PE has no Digital certificate or signature')
        elif pe_file.pe.optional_hdr.data_dirs.certificate_table.size == 0:
            return data_bytes

        if pe_file.pe.certificate_table is None and error_on_equal:
            raise Exception('Certificate table is empty')
        elif pe_file.pe.certificate_table is None:
            return data_bytes

        md5_hash1 = hashlib.md5(data_bytes).hexdigest().lower()

        # Clear memory address related to all certificates
        # for cert_entry in pe_file.pe.certificate_table.items:
        #    addr = cert_entry.pointer_to_raw_data - 8  # Must include certificate header
        #    for i in range(0, cert_entry.length):
        #        data_bytes[addr + i] = 0x00

        # Clear memory related to all certificate table
        # At certificates we must use virtual_address instead of pointer_to_raw_data
        # addr = pe_file.pe.optional_hdr.data_dirs.certificate_table.virtual_address
        # for i in range(0, pe_file.pe.optional_hdr.data_dirs.certificate_table.size):
        #    data_bytes[addr + i] = 0x00

        for entry in Tools.pe_certificate_positions(pe_file):
            addr = entry['start_addr']
            for i in range(0, entry['size']):
                data_bytes[addr + i] = 0x00

        # Zeroing values at OptionalHeader->certificate_table
        addr = pe_file.pe.optional_hdr.data_dirs.pointer_to_raw_data + 0x20
        for i in range(0, (4 * 2) + 1):  # 2 positions of Int32
            data_bytes[addr + i] = 0x00

        md5_hash2 = hashlib.md5(data_bytes).hexdigest().lower()
        if error_on_equal and md5_hash1 == md5_hash2:
            raise Exception('Nothing changed')

        return data_bytes

    @staticmethod
    def pe_certificate_positions(data: Union[bytes, str, MicrosoftPe]) -> list[dict]:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.optional_hdr.data_dirs.certificate_table.size == 0:
            return []

        # At certificates we must use virtual_address instead of pointer_to_raw_data
        yield dict(
            start_addr=pe_file.pe.optional_hdr.data_dirs.certificate_table.virtual_address,
            end_addr=pe_file.pe.optional_hdr.data_dirs.certificate_table.virtual_address +
                     pe_file.pe.optional_hdr.data_dirs.certificate_table.size,
            size=pe_file.pe.optional_hdr.data_dirs.certificate_table.size,
        )

        # Clear memory address related to all certificates
        for cert_entry in pe_file.pe.certificate_table.items:
            yield dict(
                start_addr=cert_entry.pointer_to_raw_data,
                end_addr=cert_entry.pointer_to_raw_data + cert_entry.length - 8,
                size=cert_entry.length - 8,
            )

    @staticmethod
    def pe_strip_debug(data: Union[bytes, bytearray, MicrosoftPe],
                       error_on_equal: bool = True) -> Optional[bytearray]:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        if pe_file.pe.debug_directory is None and error_on_equal:
            raise Exception('Debug table is empty')

        if pe_file.pe.debug_directory.size_of_data == 0 and error_on_equal:
            raise Exception('This PE has no Debug directory data')

        if pe_file.pe.debug_directory is None or pe_file.pe.debug_directory.size_of_data == 0:
            return data_bytes

        md5_hash1 = hashlib.md5(data_bytes).hexdigest().lower()

        addr = pe_file.pe.debug_directory.pointer_to_raw_data
        for i in range(0, pe_file.pe.debug_directory.size_of_data):
            data_bytes[addr + i] = 0x00

        n_data = bytearray([
            0x00, 0x00, 0x00, 0x00,  # characteristics
            0x00, 0x00, 0x00, 0x00,  # time_date_stamp
            0x00, 0x00,  # major_version
            0x00, 0x00,  # minor_version
            0x10, 0x00, 0x00, 0x00,  # type => Unknown
            0x00, 0x00, 0x00, 0x00,  # size_of_data
            0x00, 0x00, 0x00, 0x00,  # address_of_raw_data
            0x00, 0x00, 0x00, 0x00,  # pointer_to_raw_data
        ])

        addr = pe_file.pe.optional_hdr.data_dirs.debug.pointer_to_raw_data
        for i, v in enumerate(n_data):
            data_bytes[addr + i] = v

        md5_hash2 = hashlib.md5(data_bytes).hexdigest().lower()
        if error_on_equal and md5_hash1 == md5_hash2:
            raise Exception('Nothing changed')

        return data_bytes

    @staticmethod
    def pe_debug_positions(data: Union[bytes, str, MicrosoftPe]) -> list[dict]:
        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.debug_directory is None or pe_file.pe.debug_directory.size_of_data == 0:
            return []

        yield dict(
            start_addr=pe_file.pe.debug_directory.pointer_to_raw_data,
            end_addr=pe_file.pe.debug_directory.pointer_to_raw_data + pe_file.pe.debug_directory.size_of_data,
            size=pe_file.pe.debug_directory.size_of_data,
        )

    @staticmethod
    def pe_strip_resources(data: Union[bytes, bytearray, MicrosoftPe],
                           filter_types: Union[list[MicrosoftPe.DirectoryEntryType], None],
                           error_on_equal: bool = True) -> Optional[bytearray]:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        if pe_file.pe.resources_table is None and error_on_equal:
            raise Exception('Resource table is empty')

        if pe_file.pe.resources_table.items == 0 and error_on_equal:
            raise Exception('This PE has no Resource table items')

        if pe_file.pe.resources_table is None or pe_file.pe.resources_table.items == 0:
            return data_bytes

        md5_hash1 = hashlib.md5(data_bytes).hexdigest().lower()

        for res_entry in Tools.pe_resources_positions(pe_file, filter_types):
            addr = res_entry['start_addr']
            for i in range(0, res_entry['size']):
                data_bytes[addr + i] = 0x00

        cnt = pe_file.pe.resources_table.number_of_id_entries

        # Parse (manually) resource table to replace Resource Type to 'Undefined'
        # This change type to prevent Windows to Parsing
        empty = int(0).to_bytes(length=4, byteorder='little')
        res_addr = pe_file.pe.optional_hdr.data_dirs.resource_table.pointer_to_raw_data + 16
        for idx in range(0, pe_file.pe.resources_table.number_of_id_entries):
            e_addr = res_addr + (idx * 8)
            name_offset = int.from_bytes(data_bytes[e_addr:e_addr + 4], byteorder='little')
            if (name_offset & 0x80000000) == 0:
                name_address = MicrosoftPe.DirectoryEntryType(name_offset & 0x7FFFFFFF)
                if filter_types is None or len(filter_types) == 0 or name_address in filter_types:
                    cnt -= 1
                    data_bytes[e_addr] = empty[0]
                    data_bytes[e_addr + 1] = empty[1]
                    data_bytes[e_addr + 2] = empty[2]
                    data_bytes[e_addr + 3] = empty[3]

        b_cnt = int(cnt).to_bytes(length=2, byteorder='little')
        res_addr = pe_file.pe.optional_hdr.data_dirs.resource_table.pointer_to_raw_data + 14
        for idx, b in enumerate(b_cnt):
            data_bytes[res_addr + idx] = b

        md5_hash2 = hashlib.md5(data_bytes).hexdigest().lower()
        if error_on_equal and md5_hash1 == md5_hash2:
            raise Exception('Nothing changed')

        return data_bytes

    @staticmethod
    def pe_resources_positions(data: Union[bytes, str, MicrosoftPe],
                               filter_types: Union[list[MicrosoftPe.DirectoryEntryType], None]) -> list[dict]:
        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.resources_table is None or pe_file.pe.resources_table.items == 0:
            return []

        for res in pe_file.pe.resources_table.items:
            if res.is_directory and res.directory_table is not None \
                    and (filter_types is None or len(filter_types) == 0 or res.name_type in filter_types):
                for res1 in res.directory_table.items:
                    if res1.is_directory and res1.directory_table is not None:
                        for res2 in res1.directory_table.items:
                            yield dict(
                                start_addr=res2.pointer_to_raw_data,
                                end_addr=res2.pointer_to_raw_data + res2.data_size,
                                size=res2.data_size,
                            )

    @staticmethod
    def pe_version(data: Union[bytes, bytearray, MicrosoftPe], raise_error: bool = False) -> Optional[dict]:
        try:
            if isinstance(data, MicrosoftPe):
                data = Tools.pe_version_raw(data)

            elif isinstance(data, bytes) or isinstance(data, bytearray):
                mz = b"MZ"
                if data[0x0:0x2] == mz:
                    data = Tools.pe_version_raw(data)

            if data is None or len(data) == 0:
                return {}

            return vi.get_version_info(b'' + data)
        except Exception as ex:
            if raise_error:
                raise ex
            Tools.print_error(ex)
            return {}

    @staticmethod
    def pe_version_raw(data: Union[bytes, str, MicrosoftPe]) -> Optional[bytearray]:
        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        if pe_file.pe.resources_table is None or pe_file.pe.resources_table.items == 0:
            return None

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        try:
            for res in pe_file.pe.resources_table.items:
                if res.is_directory and res.directory_table is not None and \
                        res.name_type == MicrosoftPe.DirectoryEntryType.version:
                    for res1 in res.directory_table.items:
                        if res1.is_directory and res1.directory_table is not None:
                            for res2 in res1.directory_table.items:
                                return bytearray(
                                    data_bytes[res2.pointer_to_raw_data:res2.pointer_to_raw_data + res2.data_size])

        except:
            return None

    @staticmethod
    def pe_create_version_resource(data: Union[bytes, str, MicrosoftPe]) -> Optional[bytearray]:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        section = next(iter([
            s for s in pe_file.pe.sections
            if s.name == ".rsrc"
        ]), None)

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        if pe_file.pe.resources_table is not None and len(pe_file.pe.resources_table.items) > 0:
            res_entry: Optional[MicrosoftPe.ResourceDirectoryEntry] = None
            for res in pe_file.pe.resources_table.items:
                if res.is_directory and res.directory_table is not None and \
                        res.name_type == MicrosoftPe.DirectoryEntryType.version:
                    for res1 in res.directory_table.items:
                        if res1.is_directory and res1.directory_table is not None:
                            for res2 in res1.directory_table.items:
                                res_entry = res2

            if res_entry is not None:
                return data_bytes

        need_create = False
        # Check if we need to create resource table
        if pe_file.pe.resources_table is None or len(pe_file.pe.resources_table.items) == 0:

            if section is not None:
                raise Exception('File already has a section with the name ".rsrc"')

            last_section = sorted(pe_file.pe.sections, key=lambda s: s.virtual_address, reverse=True)[0]
            virtual_address = (last_section.virtual_address + last_section.virtual_size + 1) & 0xfffff000
            if virtual_address <= (last_section.virtual_address + last_section.virtual_size):
                virtual_address += 4096

            pointer_to_raw_data = len(data_bytes)

            n_data = bytearray(
                bytearray([0x2e, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00]) +  # name (8 bytes) => .rsrc
                int(4096).to_bytes(length=4, byteorder='little') +  # virtual_size
                int(virtual_address).to_bytes(length=4, byteorder='little') +  # virtual_address
                int(4096).to_bytes(length=4, byteorder='little') +  # size_of_raw_data
                int(pointer_to_raw_data).to_bytes(length=4, byteorder='little') +  # pointer_to_raw_data
                bytearray([0x00, 0x00, 0x00, 0x00]) +  # pointer_to_relocations
                bytearray([0x00, 0x00, 0x00, 0x00]) +  # pointer_to_linenumbers
                bytearray([0x00, 0x00]) +  # number_of_relocations
                bytearray([0x00, 0x00]) +  # number_of_linenumbers
                bytearray([0x40, 0x00, 0x00, 0x40])  # characteristics
            )

            # Add new section header
            sec_size = len(n_data)
            for i, b in enumerate(n_data):
                data_bytes[last_section.pointer_to_section_header + sec_size + i] = b

            # Update pe_header->coff_header->number_of_sections
            pointer_to_number_of_sections = int.from_bytes(data_bytes[0x3c: 0x3c + 4], byteorder='little') + 6
            s2 = int(len(pe_file.pe.sections) + 1).to_bytes(length=2, byteorder='little')
            for i, b in enumerate(s2):
                data_bytes[pointer_to_number_of_sections + i] = b

            # Add empty data at the end (pointer_to_raw_data)
            data_bytes += bytearray([0x00] * 4096)

            # Create Resource Structure
            n_data = bytearray([
                0x00, 0x00, 0x00, 0x00,  # characteristics
                0x00, 0x00, 0x00, 0x00,  # time_date_stamp
                0x00, 0x00,  # major_version
                0x00, 0x00,  # minor_version
                0x00, 0x00,  # number_of_named_entries
                0x00, 0x00,  # number_of_id_entries => Empty
            ])

            # Save the data at the new .rsrc section
            for i, b in enumerate(n_data):
                data_bytes[pointer_to_raw_data + i] = b

            # Update pe_header->optional_hdr->data_dirs->resource_dir
            optional_hdr_rsrc = pe_file.pe.optional_hdr.data_dirs.pointer_to_raw_data + 0x10
            hdr_data = int(virtual_address).to_bytes(length=4, byteorder='little')  # Resource dir RVA
            hdr_data += int(len(n_data)).to_bytes(length=4, byteorder='little')  # Resource dir Size
            for i, b in enumerate(hdr_data):
                data_bytes[optional_hdr_rsrc + i] = b

            # Update current instance of PE
            pe_file = MicrosoftPe.from_bytes(data_bytes)

        elif section is not None and section.virtual_size < 0x400:
            # is too small, lets resize

            last_section = sorted(pe_file.pe.sections, key=lambda s: s.virtual_address, reverse=True)[0]
            if last_section.virtual_address == section.virtual_address:
                # \0/ is the last sessions
                diff_size = 4096 - section.size_of_raw_data

                data_bytes += bytearray([0x00] * diff_size)

                b_size = int(4096).to_bytes(length=4, byteorder='little')

                for i, b in enumerate(b_size):
                    data_bytes[section.pointer_to_section_header + 8 + i] = b  # Virtual Size
                    data_bytes[section.pointer_to_section_header + 16 + i] = b  # Raw Size

            else:
                # is not the lest one, let's move data

                # replace the name of actual section
                n_data = bytearray([0x2e, 0x6d, 0x34, 0x76, 0x33, 0x72, 0x31, 0x63, 0x6b])  # name (8 bytes)
                for i, b in enumerate(n_data):
                    data_bytes[section.pointer_to_section_header + i] = b

                _pos = len(data_bytes)
                data_bytes += bytearray([0x00] * 4096)
                _data = data_bytes[section.pointer_to_raw_data: section.pointer_to_raw_data + section.size_of_raw_data]
                for i, b in enumerate(_data):
                    data_bytes[_pos + i] = b
                    data_bytes[section.pointer_to_raw_data + i] = 0x00

                virtual_address = (last_section.virtual_address + last_section.virtual_size + 1) & 0xfffff000
                if virtual_address <= (last_section.virtual_address + last_section.virtual_size):
                    virtual_address += 4096

                n_data = bytearray(
                    bytearray([0x2e, 0x72, 0x73, 0x72, 0x63, 0x00, 0x00, 0x00]) +  # name (8 bytes) => .rsrc
                    int(4096).to_bytes(length=4, byteorder='little') +  # virtual_size
                    int(virtual_address).to_bytes(length=4, byteorder='little') +  # virtual_address
                    int(4096).to_bytes(length=4, byteorder='little') +  # size_of_raw_data
                    int(_pos).to_bytes(length=4, byteorder='little') +  # pointer_to_raw_data
                    bytearray([0x00, 0x00, 0x00, 0x00]) +  # pointer_to_relocations
                    bytearray([0x00, 0x00, 0x00, 0x00]) +  # pointer_to_linenumbers
                    bytearray([0x00, 0x00]) +  # number_of_relocations
                    bytearray([0x00, 0x00]) +  # number_of_linenumbers
                    bytearray([0x40, 0x00, 0x00, 0x40])  # characteristics
                )

                # Add new section header
                sec_size = len(n_data)
                for i, b in enumerate(n_data):
                    data_bytes[last_section.pointer_to_section_header + sec_size + i] = b

                # Update pe_header->coff_header->number_of_sections
                pointer_to_number_of_sections = int.from_bytes(data_bytes[0x3c: 0x3c + 4], byteorder='little') + 6
                s2 = int(len(pe_file.pe.sections) + 1).to_bytes(length=2, byteorder='little')
                for i, b in enumerate(s2):
                    data_bytes[pointer_to_number_of_sections + i] = b

                # Adjust offsets
                for k, v in {
                    _pos + res2.offset_to_data:
                        int(virtual_address + (
                            res2.virtual_address - section.virtual_address
                        )).to_bytes(length=4, byteorder='little')
                    for res in pe_file.pe.resources_table.items
                    if res.is_directory and res.directory_table is not None
                    for res1 in res.directory_table.items
                    if res1.is_directory and res1.directory_table is not None
                    for res2 in res1.directory_table.items
                    if res2.is_data_entry
                }.items():
                    for i, b in enumerate(v):
                        data_bytes[k + i] = b

                # Update pe_header->optional_hdr->data_dirs->resource_dir
                optional_hdr_rsrc = pe_file.pe.optional_hdr.data_dirs.pointer_to_raw_data + 0x10
                hdr_data = int(virtual_address).to_bytes(length=4, byteorder='little')  # Resource dir RVA
                for i, b in enumerate(hdr_data):
                    data_bytes[optional_hdr_rsrc + i] = b

            #print('Writing...')
            #with open('/tmp/new_tst.exe', 'wb') as pe:
            #    pe.write(data_bytes)

            # Update current instance of PE
            pe_file = MicrosoftPe.from_bytes(data_bytes)

        if pe_file.pe.resources_table is None:
            raise Exception('Resource table not found')

        optional_hdr_rsrc = pe_file.pe.optional_hdr.data_dirs.pointer_to_raw_data + 0x10
        virtual_address = int.from_bytes(data_bytes[optional_hdr_rsrc: optional_hdr_rsrc + 4], byteorder='little')

        section = next(iter([
            s for s in pe_file.pe.sections
            if s.virtual_address <= virtual_address <= s.virtual_address +
               s.virtual_size
        ]), None)

        pointer_to_raw_data = section.pointer_to_raw_data + (virtual_address - section.virtual_address)

        header_size = sum(
            [16] +  # first resource directory
            [
                sum([
                        (8 + 16) * len(res.directory_table.items)
                    ] + [
                        8 + 16 +  # Resource Directory
                        (24 * len(res1.directory_table.items))
                        for res1 in res.directory_table.items
                        if res.is_directory and res.directory_table is not None
                        and res1.is_directory and res1.directory_table is not None
                    ])
                for idx, res in enumerate(pe_file.pe.resources_table.items)
            ] +
            [
                16 + 8 + 16 + 8 + 16 + 24
            ]
        )

        # recreate all structure
        n_data = io.BytesIO(bytearray([0x00] * header_size))
        n_data2 = bytearray()

        res_base = pe_file.pe.resources_table
        n_data.seek(0)
        n_data.write(
            int(res_base.characteristics).to_bytes(length=4, byteorder='little'))  # characteristics
        n_data.write(
            int(res_base.time_date_stamp).to_bytes(length=4, byteorder='little'))  # time_date_stamp
        n_data.write(
            int(res_base.major_version).to_bytes(length=2, byteorder='little'))  # major_version
        n_data.write(
            int(res_base.minor_version).to_bytes(length=2, byteorder='little'))  # minor_version
        n_data.write(
            int(res_base.number_of_named_entries).to_bytes(length=2, byteorder='little'))  # number_of_named_entries
        n_data.write(
            int(res_base.number_of_id_entries + 1).to_bytes(length=2, byteorder='little'))  # number_of_id_entries

        items = [
            res
            for res in pe_file.pe.resources_table.items
        ] + [
            0x10
        ]

        rd1_offset = n_data.tell()
        rd1_items_offset = n_data.tell() + (8 * len(items))
        # write all of first level
        for idx, res in enumerate(
                sorted(items,
                       key=lambda x: (x.name_offset if isinstance(x, MicrosoftPe.ResourceDirectoryEntry) else x),
                       reverse=False)
        ):
            if isinstance(res, int):
                # Create from scratch
                n_data.seek(rd1_offset + (idx * 8))
                offset = rd1_items_offset | 0x80000000
                n_data.write(int(res).to_bytes(length=4, byteorder='little'))  # name_offset => 0x10 => version
                n_data.write(int(offset).to_bytes(length=4, byteorder='little'))  # offset_to_data

                n_data.seek(rd1_items_offset)
                _pos1 = n_data.tell()
                n_data.write(bytearray([
                    0x00, 0x00, 0x00, 0x00,  # characteristics
                    0x00, 0x00, 0x00, 0x00,  # time_date_stamp
                    0x00, 0x00,  # major_version
                    0x00, 0x00,  # minor_version
                    0x00, 0x00,  # number_of_named_entries
                    0x01, 0x00,  # number_of_id_entries
                ]))

                offset = (n_data.tell() + 8) | 0x80000000
                n_data.write(int(1).to_bytes(length=4, byteorder='little'))  # name_offset = 1
                n_data.write(int(offset).to_bytes(length=4, byteorder='little'))  # offset_to_data

                n_data.write(bytearray([
                    0x00, 0x00, 0x00, 0x00,  # characteristics
                    0x00, 0x00, 0x00, 0x00,  # time_date_stamp
                    0x00, 0x00,  # major_version
                    0x00, 0x00,  # minor_version
                    0x00, 0x00,  # number_of_named_entries
                    0x01, 0x00,  # number_of_id_entries
                ]))

                offset = (n_data.tell() + 8)
                n_data.write(bytearray([0x00, 0x00, 0x00, 0x00]))  # name_offset = NULL
                n_data.write(int(offset).to_bytes(length=4, byteorder='little'))  # offset_to_data

                # This is an RVA, so must be relative of entire PE
                offset = virtual_address + header_size + len(n_data2)
                n_data.write(int(offset).to_bytes(length=4, byteorder='little'))  # virtual_address
                n_data.write(int(0x400).to_bytes(length=4, byteorder='little'))  # data_size
                n_data.write(bytearray([0x00, 0x00, 0x00, 0x00]))  # code_page
                n_data.write(bytearray([0x00, 0x00, 0x00, 0x00]))  # reserved

                # Create empty data
                n_data2 += bytearray([0x00] * 0x400)

                rd1_items_offset += n_data.tell() - _pos1

            if isinstance(res, MicrosoftPe.ResourceDirectoryEntry) and res.is_directory and res.directory_table is not None:
                n_data.seek(rd1_offset + (idx * 8))
                offset = rd1_items_offset | 0x80000000
                n_data.write(int(res.name_offset).to_bytes(length=4, byteorder='little'))  # name_offset
                n_data.write(int(offset).to_bytes(length=4, byteorder='little'))           # offset_to_data

                n_data.seek(rd1_items_offset)
                _pos1 = n_data.tell()
                n_data.write(
                    int(res.directory_table.characteristics)
                    .to_bytes(length=4, byteorder='little'))  # characteristics
                n_data.write(
                    int(res.directory_table.time_date_stamp)
                    .to_bytes(length=4, byteorder='little'))  # time_date_stamp
                n_data.write(
                    int(res.directory_table.major_version)
                    .to_bytes(length=2, byteorder='little'))  # major_version
                n_data.write(
                    int(res.directory_table.minor_version)
                    .to_bytes(length=2, byteorder='little'))  # minor_version
                n_data.write(
                    int(res.directory_table.number_of_named_entries)
                    .to_bytes(length=2, byteorder='little'))  # number_of_named_entries
                n_data.write(
                    int(res.directory_table.number_of_id_entries)
                    .to_bytes(length=2, byteorder='little'))  # number_of_id_entries

                rd2_offset = n_data.tell()
                rd2_items_offset = n_data.tell() + (8 * (
                        res.directory_table.number_of_named_entries + res.directory_table.number_of_id_entries))

                # write all 2nd level
                for idx1, res1 in enumerate(res.directory_table.items):
                    if res1.is_directory and res1.directory_table is not None:
                        n_data.seek(rd2_offset + (idx1 * 8))
                        offset = rd2_items_offset | 0x80000000
                        n_data.write(int(res1.name_offset).to_bytes(length=4, byteorder='little'))  # name_offset
                        n_data.write(int(offset).to_bytes(length=4, byteorder='little'))            # offset_to_data

                        n_data.seek(rd2_items_offset)
                        _pos2 = n_data.tell()
                        n_data.write(
                            int(res1.directory_table.characteristics)
                            .to_bytes(length=4, byteorder='little'))  # characteristics
                        n_data.write(
                            int(res1.directory_table.time_date_stamp)
                            .to_bytes(length=4, byteorder='little'))  # time_date_stamp
                        n_data.write(
                            int(res1.directory_table.major_version)
                            .to_bytes(length=2, byteorder='little'))  # major_version
                        n_data.write(
                            int(res1.directory_table.minor_version)
                            .to_bytes(length=2, byteorder='little'))  # minor_version
                        n_data.write(
                            int(res1.directory_table.number_of_named_entries)
                            .to_bytes(length=2, byteorder='little'))  # number_of_named_entries
                        n_data.write(
                            int(res1.directory_table.number_of_id_entries)
                            .to_bytes(length=2, byteorder='little'))  # number_of_id_entries

                        # write all of 3th level
                        for idx2, res2 in enumerate(res1.directory_table.items):
                            if res2.is_data_entry:
                                offset = (n_data.tell() + 8)
                                n_data.write(
                                    int(res2.name_offset).to_bytes(length=4, byteorder='little'))  # name_offset
                                n_data.write(int(offset).to_bytes(length=4, byteorder='little'))  # offset_to_data

                                # This is an RVA, so must be relative of entire PE
                                offset = virtual_address + header_size + len(n_data2)
                                n_data.write(int(offset).to_bytes(length=4, byteorder='little'))  # virtual_address
                                n_data.write(int(res2.data_size).to_bytes(length=4, byteorder='little'))  # data_size
                                n_data.write(bytearray([0x00, 0x00, 0x00, 0x00]))  # code_page
                                n_data.write(bytearray([0x00, 0x00, 0x00, 0x00]))  # reserved

                                # Copy original data
                                n_data2 += bytearray(
                                    data_bytes[res2.pointer_to_raw_data:
                                               res2.pointer_to_raw_data + res2.data_size])

                        rd2_items_offset += n_data.tell() - _pos2

                rd1_items_offset += n_data.tell() - _pos1

        n_data.seek(0)
        n_data = bytearray(n_data.read())

        if header_size != len(n_data):
            raise Exception('Integrity check error 3')

        n_data += n_data2

        # Save the data at the new .rsrc section
        for i, b in enumerate(n_data):
            data_bytes[pointer_to_raw_data + i] = b

        # Update pe_header->optional_hdr->data_dirs->resource_dir
        optional_hdr_rsrc = pe_file.pe.optional_hdr.data_dirs.pointer_to_raw_data + 0x10
        hdr_data = int(virtual_address).to_bytes(length=4, byteorder='little')  # Resource dir RVA
        hdr_data += int(len(n_data)).to_bytes(length=4, byteorder='little')  # Resource dir Size
        for i, b in enumerate(hdr_data):
            data_bytes[optional_hdr_rsrc + i] = b

        # update checksum
        data_bytes = Tools.pe_update_checksum(data_bytes)

        #print('Writing...')
        #with open('/tmp/new_tst.exe', 'wb') as pe:
        #    pe.write(data_bytes)

        # sanity check
        pe_tmp = MicrosoftPe.from_bytes(data_bytes)

        return data_bytes

    @staticmethod
    def pe_replace_version(data: Union[bytes, str, MicrosoftPe],
                           version: Union[bytes, bytearray]) -> Optional[bytearray]:

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Check version data
        try:
            ver = Tools.pe_version(version, raise_error=True)
        except Exception as e:
            Tools.print_error(e)
            raise Exception('Invalid version data')

        pe_file = MicrosoftPe.from_bytes(Tools.pe_create_version_resource(pe_file))

        if pe_file.pe.resources_table is None or pe_file.pe.resources_table.items == 0:
            raise Exception('cannot find resource directory')

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        res_entry: Optional[MicrosoftPe.ResourceDirectoryEntry] = None
        for res in pe_file.pe.resources_table.items:
            if res.is_directory and res.directory_table is not None and \
                    res.name_type == MicrosoftPe.DirectoryEntryType.version:
                for res1 in res.directory_table.items:
                    if res1.is_directory and res1.directory_table is not None:
                        for res2 in res1.directory_table.items:
                            res_entry = res2

        if res_entry is None:
            raise Exception('cannot find directory entry "version"')

        res_base = pe_file.pe.optional_hdr.data_dirs.resource_table.pointer_to_raw_data

        fi_offset = res_entry.pointer_to_raw_data
        ori_fi = bytearray(
            data_bytes[res_entry.pointer_to_raw_data:res_entry.pointer_to_raw_data + res_entry.data_size])

        # Empty actual data
        for i in range(0, len(ori_fi)):
            data_bytes[fi_offset + i] = 0x00

        section = next(iter([
            s for s in pe_file.pe.sections
            if s.pointer_to_raw_data <= res_entry.pointer_to_raw_data <= s.pointer_to_raw_data +
               s.size_of_raw_data
        ]), None)

        if section is None:
            raise Exception('cannot find PE section')

        if len(ori_fi) < len(version):
            # Actual size is not enough, we must create more space
            e_addr = res_entry.pointer_to_raw_data + res_entry.data_size

            # Check if we can increase the size of actual section
            diff = len(version)
            check_addr = section.pointer_to_raw_data + section.size_of_raw_data + diff
            while check_addr % 4 != 0:  # Check 4 bytes boundary
                check_addr += 1
                diff += 1
            if (overflow_section := next(iter([
                s for s in pe_file.pe.sections
                if s.pointer_to_raw_data <= check_addr <= s.pointer_to_raw_data + s.size_of_raw_data
            ]), None)) is not None:
                raise Exception('cannot increase section "%s" because overflow with section "%s" is detected!' %
                                (section.name, overflow_section.name))

            if (overflow_section := next(iter([
                s for s in Tools.pe_certificate_positions(pe_file)
                if s['start_addr'] <= check_addr <= s['end_addr']
            ]), None)) is not None:

                if overflow_section['end_addr'] == len(data_bytes):
                    # It is at the end of file, we can manage that
                    fi_offset = overflow_section['start_addr']

                    ori_cert = bytearray(
                        data_bytes[overflow_section['start_addr']:overflow_section['end_addr']])

                    addr = overflow_section['start_addr'] + diff
                    while addr % 4 != 0:  # Check 4 bytes boundary
                        addr += 1
                        diff += 1

                    # Increase data size
                    data_bytes += bytearray([0x00] * diff)

                    rva_bytes = int(addr).to_bytes(length=4, byteorder='little')
                    for i, b in enumerate(ori_cert):
                        data_bytes[addr + i] = b

                    # Clear trash data
                    for i in range(overflow_section['start_addr'], addr):
                        data_bytes[i] = 0x00

                    # Updating values at OptionalHeader->certificate_table->RVA
                    addr = pe_file.pe.optional_hdr.data_dirs.pointer_to_raw_data + 0x20
                    for i, b in enumerate(rva_bytes):
                        data_bytes[addr + i] = b

                else:
                    raise Exception(('cannot increase section "%s" because overflow with digital '
                                     'certificates section is detected!') % section.name)

            else:
                fi_offset = section.pointer_to_raw_data + section.size_of_raw_data

                # Increase real PE data size
                data_bytes += bytearray([0x00] * diff)

            # Update resource section
            n_data = bytearray(
                int(section.virtual_size + diff).to_bytes(length=4, byteorder='little') +  # virtual_size
                int(section.virtual_address).to_bytes(length=4, byteorder='little') +  # virtual_address
                int(section.size_of_raw_data + diff).to_bytes(length=4, byteorder='little')  # size_of_raw_data
            )

            s_addr = section.pointer_to_section_header + 8
            for i, b in enumerate(n_data):
                data_bytes[s_addr + i] = b

            # Update pe_header->optional_hdr->data_dirs->resource_dir
            optional_hdr_rsrc = pe_file.pe.optional_hdr.data_dirs.pointer_to_raw_data + 0x14
            hdr_data = int(
                int.from_bytes(data_bytes[optional_hdr_rsrc: optional_hdr_rsrc + 4], byteorder='little') + diff
            ).to_bytes(length=4, byteorder='little')  # Resource dir Size
            for i, b in enumerate(hdr_data):
                data_bytes[optional_hdr_rsrc + i] = b

        # Replace to the new one
        for i, b in enumerate(version):
            data_bytes[fi_offset + i] = b

        # Update new size and offset
        new_offset = section.virtual_address + (fi_offset - section.pointer_to_raw_data)
        offset_bytes = int(new_offset).to_bytes(length=4, byteorder='little')
        s_addr = res_entry.directory_address + res_base
        for i, b in enumerate(offset_bytes):
            data_bytes[s_addr + i] = b

        size_bytes = int(len(version)).to_bytes(length=4, byteorder='little')
        s_addr = s_addr + 4
        for i, b in enumerate(size_bytes):
            data_bytes[s_addr + i] = b

        # update checksum
        data_bytes = Tools.pe_update_checksum(data_bytes)

        # sanity check
        pe_tmp = MicrosoftPe.from_bytes(data_bytes)
        ver = Tools.pe_version(pe_tmp)

        return data_bytes

    @staticmethod
    def calc_pe_path_name(data: Union[bytes, str, MicrosoftPe]) -> str:
        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())
        sha256_hash = hashlib.sha256(data_bytes).hexdigest().lower()
        name = None
        version = None

        ver = Tools.pe_version(pe_file)
        if ver is not None and isinstance(ver, dict):
            name = ver.get('ProductName', '').strip().lower() \
                if ver.get('ProductName', None) is not None else ''
            version = ver.get('ProductVersion', '').strip().lower() \
                if ver.get('ProductVersion', None) is not None else ''

        if name != '' and version != '':
            return os.path.join(f'{name}_{version}', sha256_hash)
        elif name != '':
            return os.path.join(f'{name}', sha256_hash)
        else:
            return sha256_hash

    @staticmethod
    def resolve_path(path: str) -> Optional[str]:

        if not isinstance(path, str):
            return None

        try:
            if '~' in path:
                path = expanduser(path)

            return str(Path(path).resolve())

        except Exception as e:
            return None

    @staticmethod
    def sign_pe(data: Union[bytes, bytearray, str, MicrosoftPe, MicrosoftPeHolder],
                pkcs12: Union[bytes, bytearray, str]) -> Optional[bytearray]:

        from avsniper.util.strings import StringPart
        from avsniper.util.process import Process

        write_exe_file = True
        write_p12_file = True
        p12_name = None
        exe_name = None
        rnd = StringPart.random_string(8, 'S').decode("UTF-8")
        temp_path = str(Path(f'./avsniper_tmp_{rnd}').resolve())

        if not os.path.isdir(temp_path):
            os.mkdir(temp_path)

        try:

            if isinstance(data, str):
                if (exe_name := Tools.resolve_path(data)) is None:
                    raise Exception(f'Invalid path {data}')

                # Check if we can read and if is a valid PE
                with open(exe_name, 'rb') as pe:
                    data = bytearray(pe.read())
                    tmp = MicrosoftPe.from_bytes(data)
                    write_exe_file = False

            if exe_name is None:
                exe_name = os.path.join(temp_path, f'pkcs12_{rnd}.exe')

            if isinstance(data, MicrosoftPe):
                data = MicrosoftPeHolder.from_pe(data)

            if isinstance(data, MicrosoftPeHolder):
                data = data.to_bytes()

            if isinstance(data, bytearray):
                data = b'' + data

            if not isinstance(data, bytes):
                raise Exception('Invalid EXE data type')

            if isinstance(pkcs12, str):
                if (p12_name := Tools.resolve_path(pkcs12)) is None:
                    raise Exception(f'Invalid path {pkcs12}')

                # Check if we can read
                with open(p12_name, 'rb') as f:
                    pkcs12 = bytearray(f.read())
                    write_p12_file = False

            if p12_name is None:
                p12_name = os.path.join(temp_path, f'pkcs12_{rnd}.pfx')

            if isinstance(pkcs12, bytearray):
                pkcs12 = b'' + pkcs12

            if not isinstance(pkcs12, bytes):
                raise Exception('Invalid PKCS#12 data type')

            if write_exe_file:
                # update checksum
                data = Tools.pe_update_checksum(data)

                with open(exe_name, 'wb') as f:
                    f.write(data)

            if write_p12_file:
                with open(p12_name, 'wb') as f:
                    f.write(pkcs12)

            p = platform.system().lower()
            if p == "windows":
                status_code, stdout, stderr = Process.call(
                    command=("signtool.exe sign /td sha256 /fd sha256 /a "
                             "/tr http://timestamp.digicert.com /p 123456 "
                             f"/f \"{p12_name}\" "
                             f"\"{exe_name}\" "),
                    path_list=["C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\"],
                    cwd=temp_path
                )

                if status_code != 0:
                    from avsniper.config import Configuration
                    from avsniper.util.logger import Logger

                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot sign with the new certificates{W}')
                    if Configuration.verbose >= 3:
                        Logger.pl('{GR}%s{W}' % stderr)

                    raise Exception('Cannot sign the EXE')

            with open(exe_name, 'rb') as pe:
                return bytearray(pe.read())

        except Exception as e:
            raise e
        finally:
            shutil.rmtree(temp_path, ignore_errors=True)

    @staticmethod
    def pe_update_checksum(data: Union[bytes, str, MicrosoftPe]) -> Optional[bytearray]:
        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data)
        else:
            pe_file = data

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        # Get the offset to the CheckSum field in the OptionalHeader
        # (The offset is the same in PE32 and PE32+)
        checksum_offset = pe_file.pe.optional_hdr.pointer_to_raw_data + 0x40  # 64

        checksum = 0

        hdr_data = int(checksum).to_bytes(length=4, byteorder='little')
        for i, b in enumerate(hdr_data):
            data_bytes[checksum_offset + i] = b

        # Verify the data is dword-aligned. Add padding if needed
        #
        remainder = len(data_bytes) % 4
        data_len = len(data_bytes) + ((4-remainder) * (remainder != 0))

        for i in range( int(data_len / 4) ):
            # Skip the checksum field
            if i == int(checksum_offset / 4):
                continue
            if i+1 == (int(data_len / 4)) and remainder:
                dword = struct.unpack('I', data_bytes[i*4:] + (b'\0' * (4-remainder)) )[0]
            else:
                dword = struct.unpack('I', data_bytes[i*4: i*4+4])[0]

            checksum += dword
            if checksum >= 2**32:
                checksum = (checksum & 0xffffffff) + (checksum >> 32)

        checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = checksum + (checksum >> 16)
        checksum = checksum & 0xffff

        checksum += len(data_bytes)

        hdr_data = int(checksum).to_bytes(length=4, byteorder='little')
        for i, b in enumerate(hdr_data):
            data_bytes[checksum_offset + i] = b

        return data_bytes
