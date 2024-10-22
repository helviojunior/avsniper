# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class MicrosoftPe(KaitaiStruct):
    """
    .. seealso::
       Source - https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    """

    class PeFormat(Enum):
        rom_image = 263
        pe32 = 267
        pe32_plus = 523

    class DirectoryEntryType(Enum):
        undefined = 0
        cursor = 1
        bitmap = 2
        icon = 3
        menu = 4
        dialog = 5
        string = 6
        fontdir = 7
        font = 8
        accelerator = 9
        rcdata = 10
        messagetable = 11
        group_cursor2 = 12
        group_cursor4 = 14
        version = 16
        dlginclude = 17
        plugplay = 19
        vxd = 20
        anicursor = 21
        aniicon = 22
        html = 23
        manifest = 24
        toolbar = 241
        dlginit = 252

    class IconGroupEntryType(Enum):
        undefined = 0
        icon = 1
        cursor = 2
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.mz = MicrosoftPe.MzPlaceholder(self._io, self, self._root)

    class DotnetHeader(KaitaiStruct):

        class FlagEnum(Enum):
            unknown = 0
            il_only = 1
            required_32bit = 2
            il_library = 4
            strongnamesigned = 8
            native_entrypoint = 16
            trackdebugdata = 65536
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.cb = self._io.read_u4le()
            self.major_runtime_version = self._io.read_u2le()
            self.minor_runtime_version = self._io.read_u2le()
            self.meta_data = MicrosoftPe.DataDir(self._io, self, self._root)
            self.flags = KaitaiStream.resolve_enum(MicrosoftPe.DotnetHeader.FlagEnum, self._io.read_u4le())
            self.entry_point_token = self._io.read_u4le()
            self.entry_point_virtual_address = self._io.read_u4le()
            self.resources = MicrosoftPe.DataDir(self._io, self, self._root)
            self.strong_name_signature = MicrosoftPe.DataDir(self._io, self, self._root)
            self.code_manager_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.export_address_table_jumps = MicrosoftPe.DataDir(self._io, self, self._root)
            self.managed_native_header = MicrosoftPe.DataDir(self._io, self, self._root)


        def __repr__(self):
            return u".NET Header"

    class CertificateEntry(KaitaiStruct):
        """
        .. seealso::
           Source - https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
        """

        class CertificateRevision(Enum):
            revision_1_0 = 256
            revision_2_0 = 512

        class CertificateTypeEnum(Enum):
            x509 = 1
            pkcs_signed_data = 2
            reserved_1 = 3
            ts_stack_signed = 4
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            if self.pointer_to_raw_data < 0:
                self.save_offset = self._io.read_bytes(0)

            self.length = self._io.read_u4le()
            self.revision = KaitaiStream.resolve_enum(MicrosoftPe.CertificateEntry.CertificateRevision, self._io.read_u2le())
            self.certificate_type = KaitaiStream.resolve_enum(MicrosoftPe.CertificateEntry.CertificateTypeEnum, self._io.read_u2le())
            self.certificate_bytes = self._io.read_bytes((self.length - 8))

        @property
        def offset(self):
            if hasattr(self, '_m_offset'):
                return self._m_offset

            self._m_offset = self._io.pos()
            return getattr(self, '_m_offset', None)

        @property
        def pointer_to_raw_data(self):
            if hasattr(self, '_m_pointer_to_raw_data'):
                return self._m_pointer_to_raw_data

            self._m_pointer_to_raw_data = ((self._root.pe.optional_hdr.data_dirs.certificate_table.virtual_address + self.offset) + 8)
            return getattr(self, '_m_pointer_to_raw_data', None)


        def __repr__(self):
            return u"Certificate Entry <Type: " + str(self.certificate_type.value) + u", Length: " + str(self.length) + u", PointerToRawData: " + str(self.pointer_to_raw_data) + u">"

    class DotnetMetadataHeader(KaitaiStruct):
        """
        .. seealso::
           Source - https://www.ntcore.com/files/dotnetformat.htm
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.signature = self._io.read_u4le()
            self.major_version = self._io.read_u2le()
            self.minor_version = self._io.read_u2le()
            self.reserved = self._io.read_u4le()
            self.version_length = self._io.read_u4le()
            self.version_string = (KaitaiStream.bytes_strip_right(self._io.read_bytes(self.version_length), 0)).decode(u"UTF-8")
            self.flags = self._io.read_u2le()
            self.number_of_streams = self._io.read_u2le()
            self.streams = []
            for i in range(self.number_of_streams):
                self.streams.append(MicrosoftPe.DotnetStream(self._io, self, self._root))



        def __repr__(self):
            return u"Metadata Header <.NET Version " + self.version_string + u", NumberOfStreams: " + str(self.number_of_streams) + u">"

    class IconDirectoryEntry(KaitaiStruct):
        """
        .. seealso::
           Source - https://en.wikipedia.org/wiki/ICO_(file_format)
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.width = self._io.read_u1()
            self.height = self._io.read_u1()
            self.icon_colors = self._io.read_u1()
            self.icon_reserved = self._io.read_u1()
            self.color_planes = self._io.read_u2le()
            self.bits_per_pixel = self._io.read_u2le()
            self.byte_size = self._io.read_u4le()
            self.ordinal_id = self._io.read_u2le()


        def __repr__(self):
            return u"Icon Entry <w: " + str(self.width) + u", h: " + str(self.height) + u", Reference ID: " + str(self.ordinal_id) + u">"

    class OptionalHeaderWindows(KaitaiStruct):

        class SubsystemEnum(Enum):
            unknown = 0
            native = 1
            windows_gui = 2
            windows_cui = 3
            posix_cui = 7
            windows_ce_gui = 9
            efi_application = 10
            efi_boot_service_driver = 11
            efi_runtime_driver = 12
            efi_rom = 13
            xbox = 14
            windows_boot_application = 16
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            if self._parent.std.format == MicrosoftPe.PeFormat.pe32:
                self.image_base_32 = self._io.read_u4le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus:
                self.image_base_64 = self._io.read_u8le()

            self.section_alignment = self._io.read_u4le()
            self.file_alignment = self._io.read_u4le()
            self.major_operating_system_version = self._io.read_u2le()
            self.minor_operating_system_version = self._io.read_u2le()
            self.major_image_version = self._io.read_u2le()
            self.minor_image_version = self._io.read_u2le()
            self.major_subsystem_version = self._io.read_u2le()
            self.minor_subsystem_version = self._io.read_u2le()
            self.win32_version_value = self._io.read_u4le()
            self.size_of_image = self._io.read_u4le()
            self.size_of_headers = self._io.read_u4le()
            self.check_sum = self._io.read_u4le()
            self.subsystem = KaitaiStream.resolve_enum(MicrosoftPe.OptionalHeaderWindows.SubsystemEnum, self._io.read_u2le())
            self.dll_characteristics = self._io.read_u2le()
            if self._parent.std.format == MicrosoftPe.PeFormat.pe32:
                self.size_of_stack_reserve_32 = self._io.read_u4le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus:
                self.size_of_stack_reserve_64 = self._io.read_u8le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32:
                self.size_of_stack_commit_32 = self._io.read_u4le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus:
                self.size_of_stack_commit_64 = self._io.read_u8le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32:
                self.size_of_heap_reserve_32 = self._io.read_u4le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus:
                self.size_of_heap_reserve_64 = self._io.read_u8le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32:
                self.size_of_heap_commit_32 = self._io.read_u4le()

            if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus:
                self.size_of_heap_commit_64 = self._io.read_u8le()

            self.loader_flags = self._io.read_u4le()
            self.number_of_rva_and_sizes = self._io.read_u4le()


    class OptionalHeaderDataDirs(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            if self.pointer_to_raw_data < 0:
                self.save_offset = self._io.read_bytes(0)

            self.export_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.import_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.resource_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.exception_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.certificate_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.base_relocation_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.debug = MicrosoftPe.DataDir(self._io, self, self._root)
            self.architecture = MicrosoftPe.DataDir(self._io, self, self._root)
            self.global_ptr = MicrosoftPe.DataDir(self._io, self, self._root)
            self.tls_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.load_config_table = MicrosoftPe.DataDir(self._io, self, self._root)
            self.bound_import = MicrosoftPe.DataDir(self._io, self, self._root)
            self.iat = MicrosoftPe.DataDir(self._io, self, self._root)
            self.delay_import_descriptor = MicrosoftPe.DataDir(self._io, self, self._root)
            self.clr_runtime_header = MicrosoftPe.DataDir(self._io, self, self._root)

        @property
        def pointer_to_raw_data(self):
            if hasattr(self, '_m_pointer_to_raw_data'):
                return self._m_pointer_to_raw_data

            self._m_pointer_to_raw_data = (self._parent.pointer_to_raw_data + self._io.pos())
            return getattr(self, '_m_pointer_to_raw_data', None)


    class DotnetStream(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.offset = self._io.read_u4le()
            self.size = self._io.read_u4le()
            self.name = (self._io.read_bytes_term(0, False, True, False)).decode(u"ascii")
            self.padding = self._io.read_bytes(((4 - self._io.pos()) % 4))

        @property
        def pointer_to_raw_data(self):
            if hasattr(self, '_m_pointer_to_raw_data'):
                return self._m_pointer_to_raw_data

            self._m_pointer_to_raw_data = (self._root.pe.dotnet_header.meta_data.pointer_to_raw_data + self.offset)
            return getattr(self, '_m_pointer_to_raw_data', None)


        def __repr__(self):
            return u"Stream <Name: " + self.name + u", Offset: " + str(self.offset) + u", Size: " + str(self.size) + u", PointerToRawData: " + str(self.pointer_to_raw_data) + u">"

    class ResourceDirectoryTable(KaitaiStruct):
        def __init__(self, parent_type, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.parent_type = parent_type
            self._read()

        def _read(self):
            if self.pointer_to_header < 0:
                self.save_offset = self._io.read_bytes(0)

            self.characteristics = self._io.read_u4le()
            self.time_date_stamp = self._io.read_u4le()
            self.major_version = self._io.read_u2le()
            self.minor_version = self._io.read_u2le()
            self.number_of_named_entries = self._io.read_u2le()
            self.number_of_id_entries = self._io.read_u2le()
            self.items = []
            for i in range((self.number_of_named_entries + self.number_of_id_entries)):
                self.items.append(MicrosoftPe.ResourceDirectoryEntry(self.parent_type, self._io, self, self._root))


        @property
        def pointer_to_header(self):
            if hasattr(self, '_m_pointer_to_header'):
                return self._m_pointer_to_header

            self._m_pointer_to_header = (self._root.pe.optional_hdr.data_dirs.resource_table.pointer_to_raw_data + self._io.pos())
            return getattr(self, '_m_pointer_to_header', None)

        @property
        def has_entries(self):
            if hasattr(self, '_m_has_entries'):
                return self._m_has_entries

            self._m_has_entries = (self.number_of_named_entries + self.number_of_id_entries) > 0
            return getattr(self, '_m_has_entries', None)


        def __repr__(self):
            return u"Res dir table <Named entries: " + str(self.number_of_named_entries) + u", ID entries: " + str(self.number_of_id_entries) + u">"

    class DataDir(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.virtual_address = self._io.read_u4le()
            self.size = self._io.read_u4le()

        @property
        def sections_lookup(self):
            if hasattr(self, '_m_sections_lookup'):
                return self._m_sections_lookup

            self._m_sections_lookup = MicrosoftPe.SectionsLookup(self.virtual_address, self._io, self, self._root)
            return getattr(self, '_m_sections_lookup', None)

        @property
        def pointer_to_raw_data(self):
            if hasattr(self, '_m_pointer_to_raw_data'):
                return self._m_pointer_to_raw_data

            self._m_pointer_to_raw_data = ((self.sections_lookup.section.pointer_to_raw_data + (self.virtual_address - self.sections_lookup.section.virtual_address)) if self.sections_lookup.has_section else 0)
            return getattr(self, '_m_pointer_to_raw_data', None)


        def __repr__(self):
            return u"Data Directory <VirtualAddr: " + str(self.virtual_address) + u", Size: " + str(self.size) + u", PointerToRawData: " + str(self.pointer_to_raw_data) + u">"

    class CoffSymbol(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self._raw_name_annoying = self._io.read_bytes(8)
            _io__raw_name_annoying = KaitaiStream(BytesIO(self._raw_name_annoying))
            self.name_annoying = MicrosoftPe.Annoyingstring(_io__raw_name_annoying, self, self._root)
            self.value = self._io.read_u4le()
            self.section_number = self._io.read_u2le()
            self.type = self._io.read_u2le()
            self.storage_class = self._io.read_u1()
            self.number_of_aux_symbols = self._io.read_u1()

        @property
        def section(self):
            if hasattr(self, '_m_section'):
                return self._m_section

            self._m_section = self._root.pe.sections[(self.section_number - 1)]
            return getattr(self, '_m_section', None)

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data

            _pos = self._io.pos()
            self._io.seek((self.section.pointer_to_raw_data + self.value))
            self._m_data = self._io.read_bytes(1)
            self._io.seek(_pos)
            return getattr(self, '_m_data', None)


    class ResourceDirectoryEntry(KaitaiStruct):
        def __init__(self, parent_type, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.parent_type = parent_type
            self._read()

        def _read(self):
            if self.pointer_to_header < 0:
                self.save_offset = self._io.read_bytes(0)

            self.name_offset = self._io.read_u4le()
            self.offset_to_data = self._io.read_u4le()

        @property
        def name_address(self):
            if hasattr(self, '_m_name_address'):
                return self._m_name_address

            self._m_name_address = (self.name_offset & 2147483647)
            return getattr(self, '_m_name_address', None)

        @property
        def directory_table(self):
            if hasattr(self, '_m_directory_table'):
                return self._m_directory_table

            if self.is_directory:
                _pos = self._io.pos()
                self._io.seek(self.directory_address)
                _on = self.parent_type
                if _on == MicrosoftPe.DirectoryEntryType.undefined:
                    self._m_directory_table = MicrosoftPe.ResourceDirectoryTable(self.name_type, self._io, self, self._root)
                else:
                    self._m_directory_table = MicrosoftPe.ResourceDirectoryTable(self.parent_type, self._io, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_directory_table', None)

        @property
        def directory_address(self):
            if hasattr(self, '_m_directory_address'):
                return self._m_directory_address

            self._m_directory_address = (self.offset_to_data & 2147483647)
            return getattr(self, '_m_directory_address', None)

        @property
        def is_data_entry(self):
            if hasattr(self, '_m_is_data_entry'):
                return self._m_is_data_entry

            self._m_is_data_entry =  ((not (self.is_name_string)) and (not (self.is_directory))) 
            return getattr(self, '_m_is_data_entry', None)

        @property
        def is_directory(self):
            if hasattr(self, '_m_is_directory'):
                return self._m_is_directory

            self._m_is_directory = (self.offset_to_data & 2147483648) > 0
            return getattr(self, '_m_is_directory', None)

        @property
        def pointer_to_raw_data(self):
            if hasattr(self, '_m_pointer_to_raw_data'):
                return self._m_pointer_to_raw_data

            self._m_pointer_to_raw_data = ((self._root.pe.optional_hdr.data_dirs.resource_table.sections_lookup.section.pointer_to_raw_data + (self.virtual_address - self._root.pe.optional_hdr.data_dirs.resource_table.sections_lookup.section.virtual_address)) if self.is_data_entry else (self._root.pe.optional_hdr.data_dirs.resource_table.sections_lookup.section.pointer_to_raw_data + self.directory_address))
            return getattr(self, '_m_pointer_to_raw_data', None)

        @property
        def data_size(self):
            if hasattr(self, '_m_data_size'):
                return self._m_data_size

            if self.is_data_entry:
                _pos = self._io.pos()
                self._io.seek((self.directory_address + 4))
                self._m_data_size = self._io.read_u4le()
                self._io.seek(_pos)

            return getattr(self, '_m_data_size', None)

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data

            if self.is_data_entry:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.pointer_to_raw_data)
                _on = self.parent_type
                if _on == MicrosoftPe.DirectoryEntryType.group_cursor2:
                    self._raw__m_data = io.read_bytes(self.data_size)
                    _io__raw__m_data = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = MicrosoftPe.IconGroup(_io__raw__m_data, self, self._root)
                elif _on == MicrosoftPe.DirectoryEntryType.group_cursor4:
                    self._raw__m_data = io.read_bytes(self.data_size)
                    _io__raw__m_data = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = MicrosoftPe.IconGroup(_io__raw__m_data, self, self._root)
                else:
                    self._raw__m_data = io.read_bytes(self.data_size)
                    _io__raw__m_data = KaitaiStream(BytesIO(self._raw__m_data))
                    self._m_data = MicrosoftPe.Bin(_io__raw__m_data, self, self._root)
                io.seek(_pos)

            return getattr(self, '_m_data', None)

        @property
        def name_string(self):
            if hasattr(self, '_m_name_string'):
                return self._m_name_string

            if self.is_name_string:
                _pos = self._io.pos()
                self._io.seek(self.name_address)
                self._m_name_string = (self._io.read_bytes_term(0, False, True, False)).decode(u"ascii")
                self._io.seek(_pos)

            return getattr(self, '_m_name_string', None)

        @property
        def virtual_address(self):
            if hasattr(self, '_m_virtual_address'):
                return self._m_virtual_address

            if self.is_data_entry:
                _pos = self._io.pos()
                self._io.seek(self.directory_address)
                self._m_virtual_address = self._io.read_u4le()
                self._io.seek(_pos)

            return getattr(self, '_m_virtual_address', None)

        @property
        def pointer_to_header(self):
            if hasattr(self, '_m_pointer_to_header'):
                return self._m_pointer_to_header

            self._m_pointer_to_header = (self._root.pe.optional_hdr.data_dirs.resource_table.pointer_to_raw_data + self._io.pos())
            return getattr(self, '_m_pointer_to_header', None)

        @property
        def is_name_string(self):
            if hasattr(self, '_m_is_name_string'):
                return self._m_is_name_string

            self._m_is_name_string = (self.name_offset & 2147483648) > 0
            return getattr(self, '_m_is_name_string', None)

        @property
        def name_type(self):
            if hasattr(self, '_m_name_type'):
                return self._m_name_type

            self._m_name_type = KaitaiStream.resolve_enum(MicrosoftPe.DirectoryEntryType, (MicrosoftPe.DirectoryEntryType.undefined if self.is_name_string else self.name_address))
            return getattr(self, '_m_name_type', None)


        def __repr__(self):
            return u"Res entry <Type: " + str(self.name_type.value) + u", Name Addr: " + str(self.name_address) + u", Dir Addr: " + str(self.directory_address) + u", PointerToRawData: " + str(self.pointer_to_raw_data) + u", Virtual Addr: " + str(self.virtual_address) + u", Data Size: " + str(self.data_size) + u">"

    class PeHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.pe_signature = self._io.read_bytes(4)
            if not self.pe_signature == b"\x50\x45\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x50\x45\x00\x00", self.pe_signature, self._io, u"/types/pe_header/seq/0")
            self.coff_hdr = MicrosoftPe.CoffHeader(self._io, self, self._root)
            if self.offset_of_optional_hdr < 0:
                self.save_offset_of_optional_hdr = self._io.read_bytes(0)

            self._raw_optional_hdr = self._io.read_bytes(self.coff_hdr.size_of_optional_header)
            _io__raw_optional_hdr = KaitaiStream(BytesIO(self._raw_optional_hdr))
            self.optional_hdr = MicrosoftPe.OptionalHeader(_io__raw_optional_hdr, self, self._root)
            self.sections = []
            for i in range(self.coff_hdr.number_of_sections):
                self.sections.append(MicrosoftPe.Section(self._io, self, self._root))


        @property
        def resources_table(self):
            if hasattr(self, '_m_resources_table'):
                return self._m_resources_table

            if self.optional_hdr.data_dirs.resource_table.size > 0:
                _pos = self._io.pos()
                self._io.seek(self.optional_hdr.data_dirs.resource_table.pointer_to_raw_data)
                self._raw__m_resources_table = self._io.read_bytes(self.optional_hdr.data_dirs.resource_table.size)
                _io__raw__m_resources_table = KaitaiStream(BytesIO(self._raw__m_resources_table))
                self._m_resources_table = MicrosoftPe.ResourceDirectoryTable(MicrosoftPe.DirectoryEntryType.undefined, _io__raw__m_resources_table, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_resources_table', None)

        @property
        def certificate_table(self):
            if hasattr(self, '_m_certificate_table'):
                return self._m_certificate_table

            if self.optional_hdr.data_dirs.certificate_table.size > 0:
                _pos = self._io.pos()
                self._io.seek(self.optional_hdr.data_dirs.certificate_table.virtual_address)
                self._raw__m_certificate_table = self._io.read_bytes(self.optional_hdr.data_dirs.certificate_table.size)
                _io__raw__m_certificate_table = KaitaiStream(BytesIO(self._raw__m_certificate_table))
                self._m_certificate_table = MicrosoftPe.CertificateTable(_io__raw__m_certificate_table, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_certificate_table', None)

        @property
        def offset_of_optional_hdr(self):
            if hasattr(self, '_m_offset_of_optional_hdr'):
                return self._m_offset_of_optional_hdr

            self._m_offset_of_optional_hdr = self._io.pos()
            return getattr(self, '_m_offset_of_optional_hdr', None)

        @property
        def dotnet_header(self):
            if hasattr(self, '_m_dotnet_header'):
                return self._m_dotnet_header

            if self.optional_hdr.data_dirs.clr_runtime_header.virtual_address != 0:
                _pos = self._io.pos()
                self._io.seek(self.optional_hdr.data_dirs.clr_runtime_header.pointer_to_raw_data)
                self._raw__m_dotnet_header = self._io.read_bytes(self.optional_hdr.data_dirs.clr_runtime_header.size)
                _io__raw__m_dotnet_header = KaitaiStream(BytesIO(self._raw__m_dotnet_header))
                self._m_dotnet_header = MicrosoftPe.DotnetHeader(_io__raw__m_dotnet_header, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_dotnet_header', None)

        @property
        def debug_directory(self):
            if hasattr(self, '_m_debug_directory'):
                return self._m_debug_directory

            if self.optional_hdr.data_dirs.debug.size > 0:
                _pos = self._io.pos()
                self._io.seek(self.optional_hdr.data_dirs.debug.pointer_to_raw_data)
                self._raw__m_debug_directory = self._io.read_bytes(self.optional_hdr.data_dirs.debug.size)
                _io__raw__m_debug_directory = KaitaiStream(BytesIO(self._raw__m_debug_directory))
                self._m_debug_directory = MicrosoftPe.DebugDirectory(_io__raw__m_debug_directory, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_debug_directory', None)

        @property
        def dotnet_metadata_header(self):
            if hasattr(self, '_m_dotnet_metadata_header'):
                return self._m_dotnet_metadata_header

            if  ((self.optional_hdr.data_dirs.clr_runtime_header.virtual_address != 0) and (self.dotnet_header.meta_data.size != 0)) :
                _pos = self._io.pos()
                self._io.seek(self.dotnet_header.meta_data.pointer_to_raw_data)
                self._raw__m_dotnet_metadata_header = self._io.read_bytes(self.dotnet_header.meta_data.size)
                _io__raw__m_dotnet_metadata_header = KaitaiStream(BytesIO(self._raw__m_dotnet_metadata_header))
                self._m_dotnet_metadata_header = MicrosoftPe.DotnetMetadataHeader(_io__raw__m_dotnet_metadata_header, self, self._root)
                self._io.seek(_pos)

            return getattr(self, '_m_dotnet_metadata_header', None)


    class OptionalHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            if self.pointer_to_raw_data < 0:
                self.save_offset = self._io.read_bytes(0)

            self.std = MicrosoftPe.OptionalHeaderStd(self._io, self, self._root)
            self.windows = MicrosoftPe.OptionalHeaderWindows(self._io, self, self._root)
            self.data_dirs = MicrosoftPe.OptionalHeaderDataDirs(self._io, self, self._root)

        @property
        def pointer_to_raw_data(self):
            if hasattr(self, '_m_pointer_to_raw_data'):
                return self._m_pointer_to_raw_data

            self._m_pointer_to_raw_data = (self._parent.offset_of_optional_hdr + self._io.pos())
            return getattr(self, '_m_pointer_to_raw_data', None)


    class Section(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            if self.pointer_to_section_header < 0:
                self.save_offset = self._io.read_bytes(0)

            self.name = (KaitaiStream.bytes_strip_right(self._io.read_bytes(8), 0)).decode(u"UTF-8")
            self.virtual_size = self._io.read_u4le()
            self.virtual_address = self._io.read_u4le()
            self.size_of_raw_data = self._io.read_u4le()
            self.pointer_to_raw_data = self._io.read_u4le()
            self.pointer_to_relocations = self._io.read_u4le()
            self.pointer_to_linenumbers = self._io.read_u4le()
            self.number_of_relocations = self._io.read_u2le()
            self.number_of_linenumbers = self._io.read_u2le()
            self.characteristics = self._io.read_u4le()

        @property
        def pointer_to_section_header(self):
            if hasattr(self, '_m_pointer_to_section_header'):
                return self._m_pointer_to_section_header

            self._m_pointer_to_section_header = self._io.pos()
            return getattr(self, '_m_pointer_to_section_header', None)

        @property
        def body(self):
            if hasattr(self, '_m_body'):
                return self._m_body

            _pos = self._io.pos()
            self._io.seek(self.pointer_to_raw_data)
            self._m_body = self._io.read_bytes(self.size_of_raw_data)
            self._io.seek(_pos)
            return getattr(self, '_m_body', None)


        def __repr__(self):
            return u"Section <Name: " + self.name + u", VirtualSize: " + str(self.virtual_size) + u", VirtualAddr: " + str(self.virtual_address) + u", PointerToRawData: " + str(self.pointer_to_raw_data) + u">"

    class IconGroup(KaitaiStruct):
        """
        .. seealso::
           Source - https://en.wikipedia.org/wiki/ICO_(file_format)
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.reserved = self._io.read_u2le()
            self.image_type = KaitaiStream.resolve_enum(MicrosoftPe.IconGroupEntryType, self._io.read_u2le())
            self.number_of_entries = self._io.read_u2le()
            self.items = []
            for i in range(self.number_of_entries):
                self.items.append(MicrosoftPe.IconDirectoryEntry(self._io, self, self._root))



        def __repr__(self):
            return u"Icon Group <Type: " + str(self.image_type.value) + u", Entries: " + str(self.number_of_entries) + u">"

    class CertificateTable(KaitaiStruct):
        """As the certificates is a static data, the value of virtual address is the pointer_to_raw_data,
        so we cannot calclate pointer_to_raw_data as usual.
        """
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.items = []
            i = 0
            while not self._io.is_eof():
                self.items.append(MicrosoftPe.CertificateEntry(self._io, self, self._root))
                i += 1



    class SectionsLookup(KaitaiStruct):
        def __init__(self, virtual_address, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.virtual_address = virtual_address
            self._read()

        def _read(self):
            self.tmp_sections = []
            i = 0
            while True:
                _ = MicrosoftPe.LookupIteration(i, self.virtual_address, self._io, self, self._root)
                self.tmp_sections.append(_)
                if  ((_.found) or (not (_.has_next))) :
                    break
                i += 1

        @property
        def section(self):
            if hasattr(self, '_m_section'):
                return self._m_section

            if len(self.tmp_sections) > 0:
                self._m_section = self.tmp_sections[-1].section

            return getattr(self, '_m_section', None)

        @property
        def has_section(self):
            if hasattr(self, '_m_has_section'):
                return self._m_has_section

            self._m_has_section =  ((len(self.tmp_sections) > 0) and (self.tmp_sections[-1].found)) 
            return getattr(self, '_m_has_section', None)


        def __repr__(self):
            return u"Session lockup <VirtualAddr: " + str(self.virtual_address) + u", Sections: " + str(len(self.tmp_sections)) + u">"

    class MzPlaceholder(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(2)
            if not self.magic == b"\x4D\x5A":
                raise kaitaistruct.ValidationNotEqualError(b"\x4D\x5A", self.magic, self._io, u"/types/mz_placeholder/seq/0")
            self.data1 = self._io.read_bytes(58)
            self.ofs_pe = self._io.read_u4le()


    class OptionalHeaderStd(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.format = KaitaiStream.resolve_enum(MicrosoftPe.PeFormat, self._io.read_u2le())
            self.major_linker_version = self._io.read_u1()
            self.minor_linker_version = self._io.read_u1()
            self.size_of_code = self._io.read_u4le()
            self.size_of_initialized_data = self._io.read_u4le()
            self.size_of_uninitialized_data = self._io.read_u4le()
            self.address_of_entry_point = self._io.read_u4le()
            self.base_of_code = self._io.read_u4le()
            if self.format == MicrosoftPe.PeFormat.pe32:
                self.base_of_data = self._io.read_u4le()



    class DebugDirectory(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.characteristics = self._io.read_u4le()
            self.time_date_stamp = self._io.read_u4le()
            self.major_version = self._io.read_u2le()
            self.minor_version = self._io.read_u2le()
            self.type = self._io.read_u4le()
            self.size_of_data = self._io.read_u4le()
            self.address_of_raw_data = self._io.read_u4le()
            self.pointer_to_raw_data = self._io.read_u4le()


        def __repr__(self):
            return u"Debug dir <address_of_raw_data: " + str(self.address_of_raw_data) + u", pointer_to_raw_data: " + str(self.pointer_to_raw_data) + u">"

    class Bin(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data = self._io.read_bytes_full()


        def __repr__(self):
            return u"Binary data"

    class LookupIteration(KaitaiStruct):
        def __init__(self, idx, virtual_address, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.idx = idx
            self.virtual_address = virtual_address
            self._read()

        def _read(self):
            pass

        @property
        def section(self):
            if hasattr(self, '_m_section'):
                return self._m_section

            self._m_section = self._root.pe.sections[self.idx]
            return getattr(self, '_m_section', None)

        @property
        def found(self):
            if hasattr(self, '_m_found'):
                return self._m_found

            self._m_found =  ((self.virtual_address >= self.section.virtual_address) and (self.virtual_address <= (self.section.virtual_address + self.section.size_of_raw_data))) 
            return getattr(self, '_m_found', None)

        @property
        def next_idx(self):
            if hasattr(self, '_m_next_idx'):
                return self._m_next_idx

            self._m_next_idx = (self.idx + (1 if self.idx < self._root.pe.coff_hdr.number_of_sections else 0))
            return getattr(self, '_m_next_idx', None)

        @property
        def has_next(self):
            if hasattr(self, '_m_has_next'):
                return self._m_has_next

            self._m_has_next = self.next_idx > self.idx
            return getattr(self, '_m_has_next', None)


    class CoffHeader(KaitaiStruct):
        """
        .. seealso::
           3.3. COFF File Header (Object and Image)
        """

        class MachineType(Enum):
            unknown = 0
            i386 = 332
            r4000 = 358
            wce_mips_v2 = 361
            alpha = 388
            sh3 = 418
            sh3_dsp = 419
            sh4 = 422
            sh5 = 424
            arm = 448
            thumb = 450
            arm_nt = 452
            am33 = 467
            powerpc = 496
            powerpc_fp = 497
            ia64 = 512
            mips16 = 614
            alpha64_or_axp64 = 644
            mips_fpu = 870
            mips16_fpu = 1126
            ebc = 3772
            riscv32 = 20530
            riscv64 = 20580
            riscv128 = 20776
            loongarch32 = 25138
            loongarch64 = 25188
            amd64 = 34404
            m32r = 36929
            arm64 = 43620
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.machine = KaitaiStream.resolve_enum(MicrosoftPe.CoffHeader.MachineType, self._io.read_u2le())
            self.number_of_sections = self._io.read_u2le()
            self.time_date_stamp = self._io.read_u4le()
            self.pointer_to_symbol_table = self._io.read_u4le()
            self.number_of_symbols = self._io.read_u4le()
            self.size_of_optional_header = self._io.read_u2le()
            self.characteristics = self._io.read_u2le()

        @property
        def symbol_table_size(self):
            if hasattr(self, '_m_symbol_table_size'):
                return self._m_symbol_table_size

            self._m_symbol_table_size = (self.number_of_symbols * 18)
            return getattr(self, '_m_symbol_table_size', None)

        @property
        def symbol_name_table_offset(self):
            if hasattr(self, '_m_symbol_name_table_offset'):
                return self._m_symbol_name_table_offset

            self._m_symbol_name_table_offset = (self.pointer_to_symbol_table + self.symbol_table_size)
            return getattr(self, '_m_symbol_name_table_offset', None)

        @property
        def symbol_name_table_size(self):
            if hasattr(self, '_m_symbol_name_table_size'):
                return self._m_symbol_name_table_size

            _pos = self._io.pos()
            self._io.seek(self.symbol_name_table_offset)
            self._m_symbol_name_table_size = self._io.read_u4le()
            self._io.seek(_pos)
            return getattr(self, '_m_symbol_name_table_size', None)

        @property
        def symbol_table(self):
            if hasattr(self, '_m_symbol_table'):
                return self._m_symbol_table

            _pos = self._io.pos()
            self._io.seek(self.pointer_to_symbol_table)
            self._m_symbol_table = []
            for i in range(self.number_of_symbols):
                self._m_symbol_table.append(MicrosoftPe.CoffSymbol(self._io, self, self._root))

            self._io.seek(_pos)
            return getattr(self, '_m_symbol_table', None)


    class Annoyingstring(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            pass

        @property
        def name_from_offset(self):
            if hasattr(self, '_m_name_from_offset'):
                return self._m_name_from_offset

            if self.name_zeroes == 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(((self._parent._parent.symbol_name_table_offset + self.name_offset) if self.name_zeroes == 0 else 0))
                self._m_name_from_offset = (io.read_bytes_term(0, False, True, False)).decode(u"ascii")
                io.seek(_pos)

            return getattr(self, '_m_name_from_offset', None)

        @property
        def name_offset(self):
            if hasattr(self, '_m_name_offset'):
                return self._m_name_offset

            _pos = self._io.pos()
            self._io.seek(4)
            self._m_name_offset = self._io.read_u4le()
            self._io.seek(_pos)
            return getattr(self, '_m_name_offset', None)

        @property
        def name(self):
            if hasattr(self, '_m_name'):
                return self._m_name

            self._m_name = (self.name_from_offset if self.name_zeroes == 0 else self.name_from_short)
            return getattr(self, '_m_name', None)

        @property
        def name_zeroes(self):
            if hasattr(self, '_m_name_zeroes'):
                return self._m_name_zeroes

            _pos = self._io.pos()
            self._io.seek(0)
            self._m_name_zeroes = self._io.read_u4le()
            self._io.seek(_pos)
            return getattr(self, '_m_name_zeroes', None)

        @property
        def name_from_short(self):
            if hasattr(self, '_m_name_from_short'):
                return self._m_name_from_short

            if self.name_zeroes != 0:
                _pos = self._io.pos()
                self._io.seek(0)
                self._m_name_from_short = (self._io.read_bytes_term(0, False, True, False)).decode(u"ascii")
                self._io.seek(_pos)

            return getattr(self, '_m_name_from_short', None)


    @property
    def pe(self):
        if hasattr(self, '_m_pe'):
            return self._m_pe

        _pos = self._io.pos()
        self._io.seek(self.mz.ofs_pe)
        self._m_pe = MicrosoftPe.PeHeader(self._io, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_pe', None)


