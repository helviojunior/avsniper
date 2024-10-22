# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Parsing functions and the JSON emitter."""
import base64
import json
import struct

from .exceptions import BadHeaderError, CorruptedStringError, TruncatedInputError, ZeroStompingError


def convert(entry):
    """Convert objects to JSON serializable formats."""
    if isinstance(entry, bytes):
        # Base64 is used rather than decoding so that the exact bytes are preserved.
        return base64.standard_b64encode(entry).decode()
    else:
        raise TypeError


def get_padding(data, cursor, end=None):
    """Count the number of padding WORDs and stop when no more padding or hits end."""
    size = 2
    pad_word = b'\x00\x00'
    padding = 0

    for i in range(cursor, len(data), size):
        chunk = data[i:i+size]
        if (chunk != pad_word) or (i == end):
            break
        else:
            padding += 1

    cursor += padding * 2

    return padding, cursor


def get_wchar(data, cursor):
    """Parse one WCHAR struct member string and stop at the null terminator."""
    size = 2
    terminator = b'\x00\x00'
    wchars = list()
    offset = cursor

    for i in range(cursor, len(data), size):
        chunk = data[i:i+size]
        if chunk == terminator:
            break
        else:
            wchars.append(chunk)

    wchar_str = b''.join(wchars)

    if cursor != len(data):
        cursor += len(wchar_str) + 2

    parsed = {
        'Bytes': wchar_str,
        #'Offset': offset,
        'Decoded': wchar_str.decode('utf-16')
    }

    return parsed, cursor


def get_header(data, cursor, expected=None, boundary=False):
    """Parse the header members that exist in each struct: wLength, wValueLength, wType, szKey, and Padding."""
    sformat = 'HHH'
    wlength, wvaluelength, wtype = struct.unpack_from(sformat, data, offset=cursor)

    if boundary:
        end = cursor + wlength - wvaluelength
    else:
        end = None

    cursor += struct.calcsize(sformat)

    szkey, cursor = get_wchar(data, cursor)
    padding, cursor = get_padding(data, cursor, end)

    structure = {
        'wLength': wlength,
        'wValueLength': wvaluelength,
        'wType': wtype,
        'szKey': szkey,
        'Padding': padding
    }

    # Check if the szKey content matches the expected
    if expected is not None:
        decoded = structure['szKey']['Decoded']
        structure['szKey']['Standard'] = True if expected == decoded else False

    return structure, cursor


def get_ffi(data, cursor):
    """Parse a VS_FIXEDFILEINFO structure."""
    ffi_format = 'IHHIIIIIIIIIII'
    ffi = struct.unpack_from(ffi_format, data, cursor)

    (
        dwsignature, dwstrucversionls, dwstrucversionms, dwfileversionms, dwfileversionls,
        dwproductversionms, dwproductversionls, dwfileflagsmask, dwfileflags,
        dwfileos, dwfiletype, dwfilesubtype, dwfiledatems, dwfiledatels
    ) = ffi

    fixed_file_info = {
        'dwSignature': hex(dwsignature),
        'dwStrucVersion': {
            'Major': dwstrucversionms,
            'Minor': dwstrucversionls
        },
        'dwFileVersionMS': dwfileversionms,
        'dwFileVersionLS': dwfileversionls,
        'dwProductVersionMS': dwproductversionms,
        'dwProductVersionLS': dwproductversionls,
        'dwFileFlagsMask': {
            'Decimal': dwfileflagsmask,
            'Hexadecimal': f'{dwfileflagsmask:#010x}'
        },
        'dwFileFlags': {
            'Decimal': dwfileflags,
            'Hexadecimal': f'{dwfileflags:#010x}'
        },
        'dwFileOS': {
            'Decimal': dwfileos,
            'Hexadecimal': f'{dwfileos:#010x}'
        },
        'dwFileType': {
            'Decimal': dwfiletype,
            'Hexadecimal': f'{dwfiletype:#010x}'
        },
        'dwFileSubtype': {
            'Decimal': dwfilesubtype,
            'Hexadecimal': f'{dwfilesubtype:#010x}'
        },
        'dwFileDateMS': dwfiledatems,
        'dwFileDateLS': dwfiledatels
    }

    cursor += struct.calcsize(ffi_format)

    meta = {
        'Type': 'VS_FIXEDFILEINFO',
        'Struct': fixed_file_info
    }

    return meta, cursor


def get_fileinfo_type(data, cursor):
    """Determine the type of the FileInfo struct based on the wValueLength member of the immediate child."""
    file_info, cursor = get_header(data, cursor)
    try:
        child_header, cursor = get_header(data, cursor)
    except struct.error:
        if file_info['szKey']['Decoded'] == 'VarFileInfo':
            return 'VarFileInfo'
        elif file_info['szKey']['Decoded'] == 'StringFileInfo':
            return 'StringFileInfo'
        else:
            return 'Unknown'

    if not child_header['wValueLength']:
        return 'StringFileInfo'
    elif child_header['wType'] == 0:
        return 'VarFileInfo'
    else:
        return 'VarFileInfoStringContainer'


def process_language_code(lang_code):
    """Process the contents of a language code tuple and return a dictionary."""
    lang_id, code_page = lang_code
    low = lang_id & 0x3ff
    high = (lang_id & 0xfc00) >> 10
    value = {
        'LangID': {
            'Hexadecimal': f'{lang_id:#06x}',
            'Parsed': {
                'MajorLanguage': f'{low:#012b}',
                'SubLanguage': f'{high:#08b}'
            }
        },
        'CodePage': {
            'Decimal': code_page,
            'Hexadecimal': f'{code_page:#06x}'
        }
    }

    return value


def get_var_values(data, cursor, end):
    """Parse Var value members recursively."""
    var_value_format = 'HH'
    lang_code = struct.unpack_from(var_value_format, data, offset=cursor)
    cursor += struct.calcsize(var_value_format)

    meta = {
        'Type': 'Value',
        'Struct': process_language_code(lang_code)
    }

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_var_values(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_vars(data, cursor, end):
    """Parse Var structures recursively."""
    start = cursor
    var, cursor = get_header(data, cursor, expected='Translation', boundary=True)
    var_end = start + var['wLength']

    # The Value of Var is an array of DWORDs. Parse it recursively.
    var_children, cursor = get_var_values(data, cursor, var_end)
    var['Value'] = var_children

    meta = {
        'Type': 'Var',
        'Struct': var
    }

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_vars(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_varfileinfo(data, cursor, with_str=False):
    """Parse the outer VarFileInfo structure and call the recusive function that gets the Var children list."""
    start = cursor
    varfileinfo, cursor = get_header(data, cursor, expected='VarFileInfo')
    end = start + varfileinfo['wLength']

    # Children member of VarFileInfo struct is an array of Var structs. Parse it recursively.
    if cursor >= end:
        children = list()
    else:
        if with_str:
            children, cursor = get_strings(data, cursor, end)
        else:
            children, cursor = get_vars(data, cursor, end)
    varfileinfo['Children'] = children

    meta = {
        'Type': 'VarFileInfo',
        'Struct': varfileinfo
    }

    if with_str:
        meta['Type'] = 'Unknown'

    return meta, cursor


def get_strings(data, cursor, end):
    """Parse String structures recursively."""
    start = cursor
    string_member, cursor = get_header(data, cursor)
    string_end = start + string_member['wLength']

    # Each String has zero or one Value member WCHAR.
    if cursor >= string_end:
        string_member['Value'] = dict()
    else:
        value, cursor = get_wchar(data, cursor)
        string_member['Value'] = value

        padding, cursor = get_padding(data, cursor)
        string_member['Value']['Padding'] = padding

    meta = {
        'Type': 'String',
        #'Offset': start,
        'Struct': string_member
    }

    if cursor < string_end:
        raise CorruptedStringError(f'Potentially corrupted String structure at offset {start}')

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_strings(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_stringtables(data, cursor, end):
    """Parse StringTable array recursively and call recursive function to parse String children."""
    start = cursor
    stringtable, cursor = get_header(data, cursor)
    table_end = start + stringtable['wLength']

    # StringTable has a big endian hex string DWORD containing language info in the WCHAR szKey.
    decoded = stringtable['szKey']['Decoded']
    try:
        hd = bytes.fromhex(decoded)
    except ValueError:
        stringtable['szKey']['Standard'] = False
    else:
        lang_code = struct.unpack('!HH', hd)
        stringtable['szKey']['Parsed'] = process_language_code(lang_code)

    # Children member of StringTable struct is an array of String structs. Parse it recursively.
    if cursor >= table_end:
        str_children = list()
    else:
        str_children, cursor = get_strings(data, cursor, table_end)
    stringtable['Children'] = str_children

    meta = {
        'Type': 'StringTable',
        'Struct': stringtable
    }

    if cursor >= end:
        return [meta], cursor
    else:
        children, cursor = get_stringtables(data, cursor, end)
        children.insert(0, meta)
        return children, cursor


def get_stringfileinfo(data, cursor):
    """Parse outer StringFileInfo structure and call the recusive function that gets the StringTable children list."""
    start = cursor
    stringfileinfo, cursor = get_header(data, cursor, expected='StringFileInfo')
    end = start + stringfileinfo['wLength']

    # Children member of StringFileInfo struct is an array of StringTable structs. Parse it recursively.
    if cursor >= end:
        children = list()
    else:
        children, cursor = get_stringtables(data, cursor, end)
    stringfileinfo['Children'] = children

    meta = {
        'Type': 'StringFileInfo',
        'Struct': stringfileinfo
    }

    return meta, cursor


def get_fileinfo(data, cursor, end):
    """Parse FileInfo structures recursively, determine type for each, and call the right recursive parser."""
    fileinfo_type = get_fileinfo_type(data, cursor)

    if fileinfo_type == 'StringFileInfo':
        fileinfo, cursor = get_stringfileinfo(data, cursor)
    elif fileinfo_type == 'VarFileInfo':
        fileinfo, cursor = get_varfileinfo(data, cursor)
    elif fileinfo_type == 'VarFileInfoStringContainer':
        fileinfo, cursor = get_varfileinfo(data, cursor, with_str=True)
    else:
        header, cursor = get_header(data, cursor)
        fileinfo = {
            'Type': fileinfo_type,
            'Struct': header
        }

    if cursor >= end:
        return [fileinfo]
    else:
        children = get_fileinfo(data, cursor, end)
        children.insert(0, fileinfo)
        return children


def get_versioninfo(data):
    """Parse the outermost VS_VERSIONINFO structure."""
    if not data:
        raise ValueError('Data input is zero bytes.')

    cursor = 0
    try:
        vs_versioninfo, cursor = get_header(data, cursor, expected='VS_VERSION_INFO')
    except UnicodeDecodeError:
        raise BadHeaderError('Header is not parsable and may be corrupted.')
    end = vs_versioninfo['wLength']

    if len(data) < end:
        raise TruncatedInputError('Input data size is less than VS_VERSION_INFO structure wLength.')
    if not vs_versioninfo['szKey']['Bytes']:
        raise ZeroStompingError('VS_VERSION_INFO szKey may be overwritten with null bytes.')

    # Change key name because Padding2 added later.
    vs_versioninfo['Padding1'] = vs_versioninfo.pop('Padding')

    # If the wValueLength is zero, the VS_FIXEDFILEINFO does not exist.
    if vs_versioninfo['wValueLength'] == 52:
        fixed_file_info, cursor = get_ffi(data, cursor)
        vs_versioninfo['Value'] = fixed_file_info
        padding, cursor = get_padding(data, cursor)
        vs_versioninfo['Padding2'] = padding

    if cursor < end:
        children = get_fileinfo(data, cursor, end)
        vs_versioninfo['Children'] = children
    else:
        vs_versioninfo['Children'] = list()

    meta = {
        'Type': 'VS_VERSION_INFO',
        'Struct': vs_versioninfo
    }

    return meta


def to_json(data):
    """Parse the version info resource data provided as input."""
    parsed = get_versioninfo(data)

    output = json.dumps(parsed, default=convert)

    return output


def get_version_info(data):
    """Parse the version info resource data provided as input."""
    parsed = get_versioninfo(data)
    output = dict({
        c3.get('Struct', {}).get('szKey', {}).get('Decoded', {}):
            c3.get('Struct', {}).get('Value', {}).get('Decoded', '')
        for c1 in parsed.get('Struct', {}).get('Children', [])
        for c2 in c1.get('Struct', {}).get('Children', [])
        for c3 in c2.get('Struct', {}).get('Children', [])
        if c1.get('Type', '').lower() == 'stringfileinfo'
           and c2.get('Type', '').lower() == 'stringtable'
           and c3.get('Type', '').lower() == 'string'
    })

    return output


def get_detailed_version_info(data):
    """Parse the version info resource data provided as input."""
    parsed = get_versioninfo(data)
    output = dict({
        c3.get('Struct', {}).get('szKey', {}).get('Decoded', {}):
            c3.get('Struct', {}).get('Value', {})
        for c1 in parsed.get('Struct', {}).get('Children', [])
        for c2 in c1.get('Struct', {}).get('Children', [])
        for c3 in c2.get('Struct', {}).get('Children', [])
        if c1.get('Type', '').lower() == 'stringfileinfo'
           and c2.get('Type', '').lower() == 'stringtable'
           and c3.get('Type', '').lower() == 'string'
    })

    return output
