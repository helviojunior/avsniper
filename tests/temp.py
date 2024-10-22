import re
import struct
import sys, json
from io import BytesIO
from pathlib import Path
import tempfile, os
from typing import Union

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.color import Color
from avsniper.util.logger import Logger
from avsniper.util.process import Process
from avsniper.util.tools import Tools

cmd = f"objdump -d -Mintel \"./tests/test_native.exe\""

pe_file = MicrosoftPe.from_file("./tests/test_native.exe")

text_offset = 0
for s in pe_file.pe.sections:
    if s.name == '.text':
        text_offset = s.virtual_address - s.pointer_to_raw_data

print(text_offset)

(code, out, err) = Process.call(cmd)
if code != 0:
    if err is not None and out is not None and len(err) == 0 and len(out) > 0:
        err = out
    Logger.pl('{!} {R}Error disassembling data {R}: %s{W}' % err)
    sys.exit(0)

out = out.replace('\r', '').replace('\t', '    ')

last_addr = max([
    m.group(1).strip().zfill(8)
    for m in re.finditer('(^[a-fA-F0-9 ]{1,20}):', out, re.IGNORECASE + re.MULTILINE)
] + ['00000000'])

# Add fake function name
out += f'\n{last_addr} <end_of_file>:\n'

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

prefix = ''
highlight_address = 0x004021f9
highlight_size = 50

min_addr = [x for x in functions.keys()][0]
max_addr = 0x00410000

dump = ''
for fnc_addr, fnc in functions.items():
    tmp = prefix + ' ' + f'\n{prefix} '.join([
        (('{O} → %s:{GR} ' if ln_addr <= highlight_address < ln_addr + len(data['hex']) else
          ('{O}   %s:{GR} ' if highlight_address < ln_addr < highlight_address + highlight_size
           else '   {GR}%s: ')
          ) % (
             ''.join([f'{x:02x}' for x in struct.pack('>I', ln_addr)])
         ).zfill(8)) +
        Tools.ljust(' '.join([
                    ('{R}%s{GR}' if highlight_address <= ln_addr + idx < highlight_address + highlight_size else '%s') %
                    x for idx, x in
                    enumerate(data['hex'])
                ]), 25) +
        ('{C}%s{GR}' if (highlight_address <= ln_addr < highlight_address + highlight_size or
                         ln_addr <= highlight_address < ln_addr + len(data['hex'])) else '%s') % data['instruction']
        for ln_addr, data in fnc['instructions'].items()
        if min_addr <= ln_addr <= max_addr
    ]) + '\n'
    if '→' in tmp or \
            (fnc_addr <= highlight_address <= fnc_addr + fnc['size'] or
             fnc_addr <= highlight_address + highlight_size <= fnc_addr + fnc['size']):
        dump += prefix + ("\033[35mFunction: {O}%s{GR}\n%s" % (fnc['name'], tmp)) + '\n'

Logger.pl(dump)
