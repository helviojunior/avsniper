import re
import struct
from io import BytesIO
from pathlib import Path
import tempfile, os
from typing import Union

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.logger import Logger
from avsniper.util.microsoft_pe_holder import MicrosoftPeHolder
from avsniper.util.process import Process
from avsniper.util.tools import Tools


class Disassembler:
    assembled_data = None
    platform = None
    arch = "i386"
    pe_file = None
    o_file = None
    text_offset = 0

    def __init__(self, data: Union[bytes, str, MicrosoftPe]):

        if not isinstance(data, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            self.pe_file = MicrosoftPeHolder.from_bytes(data)
        else:
            self.pe_file = MicrosoftPeHolder.from_pe(data)

        if self.pe_file.pe.optional_hdr.std.format.value == 0x10b:
            self.text_offset = self.pe_file.pe.optional_hdr.windows.image_base_32
        elif self.pe_file.pe.optional_hdr.std.format.value == 0x20b:
            self.text_offset = self.pe_file.pe.optional_hdr.windows.image_base_64

        for s in self.pe_file.pe.sections:
            if s.name == '.text':
                self.text_offset += s.virtual_address - s.pointer_to_raw_data

    def dump(self,
             highlight_address: int = None,
             highlight_size: int = 0,
             show_only_highlighted: bool = False,
             prefix: str = ' '
             ) -> str:

        if self.pe_file.pe.optional_hdr.std.format.value == 0x10b:
            self.arch = "i386"
        elif self.pe_file.pe.optional_hdr.std.format.value == 0x20b:
            self.arch = "x86_64"

        filename = os.path.join(tempfile.mkdtemp(), 'disass.exe')
        if os.path.isfile(filename):
            os.unlink(filename)

        self.o_file = Path(filename)

        with open(self.o_file, 'wb') as f:
            f.write(self.pe_file.to_bytes())

        cmd = f"objdump -d -Mintel \"{self.o_file.resolve()}\""

        (code, out, err) = Process.call(cmd)
        try:
            if code != 0:
                if err is not None and out is not None and len(err) == 0 and len(out) > 0:
                    err = out
                Logger.pl('{!} {R}Error disassembling data {R}: %s{W}' % err)
                return ''
        finally:
            try:
                os.unlink(filename)
            except:
                pass

        out = out.replace('\r', '').replace('\t', '    ')

        last_addr = max([
                            m.group(1).strip().zfill(8)
                            for m in re.finditer('(^[a-fA-F0-9 ]{1,20}):', out, re.IGNORECASE + re.MULTILINE)
                        ] + ['00000000'])

        # Add fake function name
        out += f'\n{last_addr} <end_of_file>:\n'

        min_addr = self.text_offset
        max_addr = int.from_bytes(bytearray([
                        int(x, 16) for x in [last_addr[i:i + 2] for i in range(0, len(last_addr), 2)]
                        if x.strip() != ''
                    ]), byteorder='big') + 1024

        functions = {}
        last = None

        for m in re.finditer(r'(^[a-fA-F0-9 ]{1,20})<(.*)>:', out, re.IGNORECASE + re.MULTILINE):
            if last is None:
                last = m
                continue
            m_addr = m.group(1).strip().zfill(8)
            s_addr = last.group(1).strip().zfill(8)
            f_addr = int.from_bytes(bytearray([
                int(x, 16) for x in [s_addr[i:i + 2] for i in range(0, len(s_addr), 2)]
                if x.strip() != ''
            ]), byteorder='big')
            functions[f_addr] = dict(
                address=f_addr,
                name=last.group(2).strip(),
                instructions={
                    (int.from_bytes(bytearray([
                        int(x, 16) for x in [s_addr[i:i + 2] for i in range(0, len(s_addr), 2)]
                        if x.strip() != ''
                    ]), byteorder='big')): dict(
                        hex=[
                            x.strip() for x in l_data.lstrip()[0:25].strip().split(' ')
                            if x.strip() != ''
                        ],
                        instruction=' '.join([
                            x.ljust(7) if i == 0 else x.lstrip()
                            for i, x in
                            enumerate(l_data.lstrip(' ')[25:].lstrip().split(' ', 2))
                        ])
                    )
                    for l in out[last.start():m.start()].strip('\n').split('\n')
                    if (search := re.search('(^[a-fA-F0-9 ]{1,20}):(.*)', l, re.IGNORECASE)) is not None
                       and (l_data := search.group(2)) is not None
                       and (s_addr := search.group(1).strip().zfill(8)) is not None
                },
                size=int.from_bytes(bytearray([
                    int(x, 16) for x in [m_addr[i:i + 2] for i in range(0, len(m_addr), 2)]
                    if x.strip() != ''
                ]), byteorder='big') - f_addr
            )
            last = m

        # order by address
        functions = dict(sorted(functions.items()))

        if highlight_address is None:
            highlight_address = -1
        else:
            highlight_address += self.text_offset

        # the file is stripped, filter function lines
        if show_only_highlighted and len(functions) == 1 and highlight_address > 0 and highlight_size > 0:
            min_addr = highlight_address - 48
            max_addr = highlight_address + highlight_size + 48

        dump = ''
        for fnc_addr, fnc in functions.items():
            tmp = prefix + ' ' + f'\n{prefix} '.join([
                (('{O} → %s:{GR}  ' if ln_addr <= highlight_address < ln_addr + len(data['hex']) else
                  ('{O}   %s:{GR}  ' if highlight_address < ln_addr < highlight_address + highlight_size
                   else '   {GR}%s:  ')
                  ) % (
                     ''.join([f'{x:02x}' for x in struct.pack('>I', ln_addr)])
                 ).zfill(8)) +
                Tools.ljust(' '.join([
                    ('{R}%s{GR}' if highlight_address <= ln_addr + idx < highlight_address + highlight_size else '%s') %
                    x for idx, x in
                    enumerate(data['hex'])
                ]), 25) +
                ('{C}%s{GR}' if (highlight_address <= ln_addr < highlight_address + highlight_size or
                                 ln_addr <= highlight_address < ln_addr + len(data['hex'])) else '%s') % data[
                    'instruction']
                for ln_addr, data in fnc['instructions'].items()
                if min_addr <= ln_addr <= max_addr
            ]) + '\n'
            if not show_only_highlighted or \
                    '→' in tmp or \
                    (fnc_addr <= highlight_address <= fnc_addr + fnc['size'] or
                     fnc_addr <= highlight_address + highlight_size <= fnc_addr + fnc['size']):
                dump += prefix + ("\033[35mFunction: {O}%s{GR}\n%s" % (fnc['name'], tmp)) + '\n'

        return dump + '{W}' if dump != '' else ''
