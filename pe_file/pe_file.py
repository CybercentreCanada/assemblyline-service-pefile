from __future__ import absolute_import

import hashlib
import json
import os
import re
import time
import traceback
from io import StringIO, BytesIO

import chardet
import pathlib2 as pathlib
import pefile
from apiscout import ApiVector
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline.common.hexdump import hexdump
from assemblyline.common.str_utils import safe_str, translate_str
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from signify import signed_pe, authenticode, context
from signify.exceptions import SignedPEParseError, AuthenticodeVerificationError, VerificationError, ParseError

from pe_file.LCID import LCID as G_LCID
from pe_file.pyimpfuzzy import pyimpfuzzy

PEFILE_SLACK_LENGTH_TO_DISPLAY = 256


class PEFile(ServiceBase):
    def __init__(self, config=None):
        super(PEFile, self).__init__(config)
        # Service Initialization
        self.log.debug("LCID DB loaded (%s entries). Running information parsing..." % (len(G_LCID),))
        self.filesize_from_peheader = -1
        self.print_slack = False
        self.pe_file = None
        self._sect_list = None
        self.entropy_warning = False
        self.file_res = None
        self.unexpected_sname = []
        self.import_hash = None
        self.filename = None
        self.patch_section = None
        self.request = None
        self.path = None
        self.apivector = None
        self.impfuzzy = None

        more_trusted_certs = self.config.get("trusted_certs", [])
        for cert_path in more_trusted_certs:
            p = pathlib.Path(cert_path)
            if p.exists():
                authenticode.TRUSTED_CERTIFICATE_STORE.extend(
                    context.FileSystemCertificateStore(location=p, trusted=True))
            else:
                self.log.error(
                    "%s was given as an additional path for trusted certs, but it doesn't appear to exist" % cert_path)

    def start(self):
        self.log.info("apiscout appears to be installed, using apiscout")
        # initialize the apivector object with the vector definition
        api_vector_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "apivector", "winapi1024v1.txt")
        self.log.info("Using apivector file: %s" % api_vector_file)
        if not os.path.exists(api_vector_file) or not os.path.isfile(api_vector_file):
            self.log.error("There appears to be something wrong with the "
                           "API vector file definition %s" % api_vector_file)
        self.apivector = ApiVector.ApiVector(winapi1024_filepath=api_vector_file)

    def get_imphash(self):
        return self.pe_file.get_imphash()

    # noinspection PyPep8Naming
    def get_pe_info(self, lcid):
        """Dumps the PE header as Results in the FileResult."""

        # PE Header
        pe_header_res = ResultSection("PE: HEADER")

        # PE Header: Header Info
        pe_header_info_res = ResultSection("[HEADER INFO]", parent=pe_header_res)
        pe_header_info_res.add_line("Entry point address: 0x%08X" % self.pe_file.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe_header_info_res.add_line("Linker Version: %02d.%02d" % (self.pe_file.OPTIONAL_HEADER.MajorLinkerVersion,
                                                                   self.pe_file.OPTIONAL_HEADER.MinorLinkerVersion))
        pe_header_info_res.add_line("OS Version: %02d.%02d" %
                                    (self.pe_file.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                                     self.pe_file.OPTIONAL_HEADER.MinorOperatingSystemVersion))
        pe_header_info_res.add_line(f"Time Date Stamp: {time.ctime(self.pe_file.FILE_HEADER.TimeDateStamp)}"
                                    f" ({str(self.pe_file.FILE_HEADER.TimeDateStamp)})")
        pe_header_info_res.add_tag("file.pe.linker.timestamp", self.pe_file.FILE_HEADER.TimeDateStamp)
        try:
            pe_header_info_res.add_line("Machine Type: %s (%s)" % (
                hex(self.pe_file.FILE_HEADER.Machine), pefile.MACHINE_TYPE[self.pe_file.FILE_HEADER.Machine]))
        except KeyError:
            pass

        # PE Header: Rich Header
        # noinspection PyBroadException
        try:

            if self.pe_file.RICH_HEADER is not None:
                pe_rich_header_info = ResultSection("[RICH HEADER INFO]", parent=pe_header_res)
                values_list = self.pe_file.RICH_HEADER.values
                pe_rich_header_info.add_line("VC++ tools used:")
                for i in range(0, int(len(values_list) / 2)):
                    line = "Tool Id: %3d Version: %6d Times used: %3d" % (
                        values_list[2 * i] >> 16, values_list[2 * i] & 0xFFFF, values_list[2 * i + 1])
                    pe_rich_header_info.add_line(line)
        except Exception:
            self.log.exception("Unable to parse PE Rich Header")

        # PE Header: Data Directories
        pe_dd_res = ResultSection("[DATA DIRECTORY]", parent=pe_header_res)
        for data_directory in self.pe_file.OPTIONAL_HEADER.DATA_DIRECTORY:
            if data_directory.Size or data_directory.VirtualAddress:
                pe_dd_res.add_line("%s - va: 0x%08X - size: 0x%08X"
                                   % (data_directory.name[len("IMAGE_DIRECTORY_ENTRY_"):],
                                      data_directory.VirtualAddress, data_directory.Size))

        # PE Header: Sections
        pe_sec_res = ResultSection("[SECTIONS]", parent=pe_header_res)

        self._init_section_list()

        try:
            for (sname, section, sec_md5, sec_entropy) in self._sect_list:

                # Create a new subsection
                section_io = BytesIO(section.get_data())
                (entropy, part_entropies) = calculate_partition_entropy(section_io)

                entropy_graph_data = {
                    'type': 'colormap',
                    'data': {
                        'domain': [0, 8],
                        'values': part_entropies
                    }
                }

                pe_subsec = ResultSection(
                    "%s - Virtual: 0x%08X (0x%08X bytes)"
                    " - Physical: 0x%08X (0x%08X bytes) - "
                    "hash: %s - entropy: %f " % (safe_str(sname), section.VirtualAddress, section.Misc_VirtualSize,
                                                 section.PointerToRawData, section.SizeOfRawData,
                                                 sec_md5, round(entropy, 3)),
                    body_format=BODY_FORMAT.GRAPH_DATA,
                    body=json.dumps(entropy_graph_data))
                pe_subsec.add_tag('file.pe.sections.hash', sec_md5)
                if sname:
                    if isinstance(sname, bytes):
                        method = chardet.detect(sname).get('encoding', 'utf-8')
                        sname = sname.decode(method)
                    pe_subsec.add_tag('file.pe.sections.name', sname)
                if entropy > 7.5:
                    pe_subsec.set_heuristic(4)
                pe_sec_res.add_subsection(pe_subsec)

        except AttributeError:
            pass

        self.file_res.add_section(pe_header_res)

        # debug
        try:
            directory = next(item for item in self.pe_file.DIRECTORY_ENTRY_DEBUG if item.entry is not None)
            debug_time_date_stamp = directory.struct.TimeDateStamp
            if debug_time_date_stamp:
                pe_debug_res = ResultSection("PE: DEBUG")
                self.file_res.add_section(pe_debug_res)

                pe_debug_res.add_line("Time Date Stamp: %s" % time.ctime(debug_time_date_stamp))

                char_enc_guessed = translate_str(directory.entry.PdbFileName)
                pdb_filename = char_enc_guessed['converted']
                pe_debug_res.add_line(f"PDB: {pdb_filename} - encoding:{char_enc_guessed['encoding']} "
                                      f"confidence:{char_enc_guessed['confidence']}")
                pe_debug_res.add_tag('file.pe.pdb_filename', pdb_filename)

        except AttributeError:
            pass
        except StopIteration:
            pass

        # imports
        try:
            if hasattr(self.pe_file, 'DIRECTORY_ENTRY_IMPORT') and len(self.pe_file.DIRECTORY_ENTRY_IMPORT) > 0:
                pe_import_res = ResultSection("PE: IMPORTS")

                pe_import_res.add_tag('file.pe.imports.sorted_sha1', self.get_import_hash())
                imphash = self.get_imphash()
                if imphash != '':
                    pe_import_res.add_tag('file.pe.imports.md5', imphash)
                pe_import_res.add_tag('file.pe.imports.fuzzy', self.impfuzzy.get_impfuzzy(sort=False))
                pe_import_res.add_tag('file.pe.imports.sorted_fuzzy', self.impfuzzy.get_impfuzzy(sort=True))
                self.file_res.add_section(pe_import_res)

                for entry in self.pe_file.DIRECTORY_ENTRY_IMPORT:
                    pe_import_dll_res = ResultSection(f"[{safe_str(entry.dll)}]", parent=pe_import_res)
                    first_element = True
                    line = StringIO()
                    for imp in entry.imports:
                        if first_element:
                            first_element = False
                        else:
                            line.write(", ")

                        if imp.name is None:
                            line.write(str(imp.ordinal))
                        else:
                            line.write(imp.name.decode())

                    pe_import_dll_res.add_line(line.getvalue())

            else:
                pe_import_res = ResultSection("PE: NO IMPORTS DETECTED ")
                self.file_res.add_section(pe_import_res)

        except AttributeError:
            pass

        # exports
        try:
            if self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp is not None:
                pe_export_res = ResultSection("PE: EXPORTS")
                # noinspection PyBroadException
                try:
                    pe_export_res.add_line(f"Module Name: {safe_str(self.pe_file.ModuleName)}")
                    pe_export_res.add_tag('file.string.extracted', safe_str(self.pe_file.ModuleName))
                    pe_export_res.add_tag('file.pe.exports.module_name', safe_str(self.pe_file.ModuleName))
                except Exception:
                    pass

                if self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp == 0:
                    pe_export_res.add_line("Time Date Stamp: 0")
                else:
                    pe_export_res.add_line(f"Time Date Stamp: "
                                           f"{time.ctime(self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp)}")

                first_element = True
                txt = []
                for exp in self.pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                    if first_element:
                        first_element = False
                    else:
                        txt.append(", ")

                    txt.append(str(exp.ordinal))
                    if exp.name is not None:
                        txt.append(f": {safe_str(exp.name)}")
                        pe_export_res.add_tag('file.pe.exports.function_name', safe_str(exp.name))

                pe_export_res.add_line(txt)

                self.file_res.add_section(pe_export_res)
        except AttributeError:
            pass

        # resources
        try:
            if len(self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries) > 0:
                pe_resource_res = ResultSection("PE: RESOURCES")
                self.file_res.add_section(pe_resource_res)

                for res_entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                    if res_entry.name is None:
                        # noinspection PyBroadException
                        try:
                            entry_name = pefile.RESOURCE_TYPE[res_entry.id]
                        except Exception:
                            # pylint: disable-msg=W0702
                            # unfortunately this code was done before we started to really care about which
                            # exception to catch so, I actually don't really know at this point, would need to try
                            # out :-\
                            entry_name = "UNKNOWN"
                    else:
                        entry_name = res_entry.name
                        pe_resource_res.add_tag('file.pe.resources.name', safe_str(entry_name, force_str=True))

                    for name_id in res_entry.directory.entries:
                        if name_id.name is None:
                            name_id.name = hex(name_id.id)
                        else:
                            pe_resource_res.add_tag('file.pe.resources.name', safe_str(name_id.name, force_str=True))

                        for language in name_id.directory.entries:
                            try:
                                language_desc = lcid[language.id]
                            except KeyError:
                                language_desc = 'Unknown language'

                            line = []
                            if res_entry.name is None:
                                line.append(entry_name)
                            else:
                                line.append(str(entry_name))

                            line.append(" " + str(name_id.name) + " ")
                            line.append("0x")
                            # this will add a link to search in AL for the value
                            line.append("%04X" % language.id)
                            pe_resource_res.add_tag('file.pe.resources.language', "%04X" % language.id)
                            line.append(" (%s)" % language_desc)

                            # get the size of the resource
                            res_size = language.data.struct.Size
                            line.append(" Size: 0x%x" % res_size)

                            pe_resource_res.add_line(line)

        except AttributeError:
            pass

        # Resources-VersionInfo
        try:
            if len(self.pe_file.FileInfo) > 2:
                pass

            for file_info in self.pe_file.FileInfo:
                for file_info_type in file_info:
                    if file_info_type.name == "StringFileInfo":
                        if len(file_info_type.StringTable) > 0:
                            pe_resource_verinfo_res = ResultSection("PE: RESOURCES-VersionInfo")
                            self.file_res.add_section(pe_resource_verinfo_res)

                            lang_id = None
                            try:
                                lang_id = file_info_type.StringTable[0].LangID.decode()
                                if lang_id:
                                    if not int(lang_id, 16) >> 16 == 0:
                                        txt = ('LangId: ' + lang_id + " (" + lcid[
                                            int(lang_id, 16) >> 16] + ")")
                                        pe_resource_verinfo_res.add_line(txt)
                                    else:
                                        txt = ('LangId: ' + lang_id + " (NEUTRAL)")
                                        pe_resource_verinfo_res.add_line(txt)
                            except (ValueError, KeyError):
                                if lang_id is not None:
                                    pe_resource_verinfo_res.add_line(f'LangId: {lang_id} is invalid')

                            for entry in file_info_type.StringTable[0].entries.items():
                                txt = f'{entry[0]}: {entry[1]}'
                                if entry[0].decode() == 'OriginalFilename':
                                    filename = entry[1].decode()
                                    pe_resource_verinfo_res.add_tag('file.pe.versions.filename', entry[1])
                                    pe_header_res.add_line(f"Original Filename: {filename}")
                                    pe_header_res.add_tag("file.pe.versions.filename", filename)
                                elif entry[0].decode() == 'FileDescription':
                                    file_desc = entry[1].decode()
                                    pe_resource_verinfo_res.add_tag('file.pe.versions.description', file_desc)
                                    pe_header_res.add_line(f"Description: {file_desc}")
                                    pe_header_res.add_tag("file.pe.versions.description", file_desc)

                                pe_resource_verinfo_res.add_line(txt)

        except AttributeError:
            pass

        # Resources Strings
        try:
            BYTE = 1
            WORD = 2
            DWORD = 4

            DS_SETFONT = 0x40

            DIALOG_LEAD = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
            DIALOG_ITEM_LEAD = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD

            DIALOGEX_LEAD = WORD + WORD + DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
            DIALOGEX_TRAIL = WORD + WORD + BYTE + BYTE
            DIALOGEX_ITEM_LEAD = DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + DWORD
            DIALOGEX_ITEM_TRAIL = WORD

            ITEM_TYPES = {0x80: "BUTTON", 0x81: "EDIT", 0x82: "STATIC", 0x83: "LIST BOX", 0x84: "SCROLL BAR",
                          0x85: "COMBO BOX"}

            if hasattr(self.pe_file, 'DIRECTORY_ENTRY_RESOURCE'):
                for dir_type in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                    if dir_type.name is None:
                        if dir_type.id in pefile.RESOURCE_TYPE:
                            dir_type.name = pefile.RESOURCE_TYPE[dir_type.id]
                    for nameID in dir_type.directory.entries:
                        if nameID.name is None:
                            nameID.name = hex(nameID.id)
                        for language in nameID.directory.entries:
                            strings = []
                            if str(dir_type.name) == "RT_DIALOG":
                                data_rva = language.data.struct.OffsetToData
                                size = language.data.struct.Size
                                data = self.pe_file.get_memory_mapped_image()[data_rva:data_rva + size]

                                offset = 0
                                if self.pe_file.get_word_at_rva(data_rva + offset) == 0x1 \
                                        and self.pe_file.get_word_at_rva(data_rva + offset + WORD) == 0xFFFF:
                                    # Use Extended Dialog Parsing

                                    # Remove leading bytes
                                    offset += DIALOGEX_LEAD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += WORD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += WORD

                                    # Get window title
                                    window_title = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                    if len(window_title) != 0:
                                        strings.append(("DIALOG_TITLE", window_title))
                                    offset += len(window_title) * 2 + WORD

                                    # Remove trailing bytes
                                    offset += DIALOGEX_TRAIL
                                    offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                    # alignment adjustment
                                    if (offset % 4) != 0:
                                        offset += WORD

                                    while True:

                                        if offset >= size:
                                            break

                                        offset += DIALOGEX_ITEM_LEAD

                                        # Get item type
                                        if self.pe_file.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                            offset += WORD
                                            type_id = self.pe_file.get_word_at_rva(data_rva + offset)
                                            try:
                                                item_type = ITEM_TYPES[type_id]
                                            except KeyError:
                                                item_type = f"UNKNOWN_{type_id}"
                                            offset += WORD
                                        else:
                                            item_type = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                            offset += len(item_type) * 2 + WORD

                                        # Get item text
                                        item_text = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                        if len(item_text) != 0:
                                            strings.append((item_type, item_text))
                                        offset += len(item_text) * 2 + WORD

                                        extra_bytes = self.pe_file.get_word_at_rva(data_rva + offset)
                                        offset += extra_bytes + DIALOGEX_ITEM_TRAIL

                                        # Alignment adjustment
                                        if (offset % 4) != 0:
                                            offset += WORD

                                else:
                                    # TODO: Use Non extended Dialog Parsing
                                    # Remove leading bytes
                                    style = self.pe_file.get_word_at_rva(data_rva + offset)

                                    offset += DIALOG_LEAD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD
                                    if data[offset:offset + 2] == "\xFF\xFF":
                                        offset += DWORD
                                    else:
                                        offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                    # Get window title
                                    window_title = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                    if len(window_title) != 0:
                                        strings.append(("DIALOG_TITLE", window_title))
                                    offset += len(window_title) * 2 + WORD

                                    if (style & DS_SETFONT) != 0:
                                        offset += WORD
                                        offset += len(self.pe_file.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                    # Alignment adjustment
                                    if (offset % 4) != 0:
                                        offset += WORD

                                    while True:

                                        if offset >= size:
                                            break

                                        offset += DIALOG_ITEM_LEAD

                                        # Get item type
                                        if self.pe_file.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                            offset += WORD
                                            item_type = ITEM_TYPES[self.pe_file.get_word_at_rva(data_rva + offset)]
                                            offset += WORD
                                        else:
                                            item_type = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                            offset += len(item_type) * 2 + WORD

                                        # Get item text
                                        if self.pe_file.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                            offset += DWORD
                                        else:
                                            item_text = self.pe_file.get_string_u_at_rva(data_rva + offset)
                                            if len(item_text) != 0:
                                                strings.append((item_type, item_text))
                                            offset += len(item_text) * 2 + WORD

                                        extra_bytes = self.pe_file.get_word_at_rva(data_rva + offset)
                                        offset += extra_bytes + WORD

                                        # Alignment adjustment
                                        if (offset % 4) != 0:
                                            offset += WORD

                            elif str(dir_type.name) == "RT_STRING":
                                data_rva = language.data.struct.OffsetToData
                                size = language.data.struct.Size
                                data = self.pe_file.get_memory_mapped_image()[data_rva:data_rva + size]
                                offset = 0
                                while True:
                                    if offset >= size:
                                        break

                                    ustr_length = self.pe_file.get_word_from_data(data[offset:offset + 2], 0)
                                    offset += 2

                                    if ustr_length == 0:
                                        continue

                                    ustr = self.pe_file.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
                                    offset += ustr_length * 2
                                    strings.append((None, ustr))

                            if len(strings) > 0:
                                success = False
                                try:
                                    comment = "%s (id:%s - lang_id:0x%04X [%s])" % (
                                        str(dir_type.name), str(nameID.name), language.id, lcid[language.id])
                                except KeyError:
                                    comment = "%s (id:%s - lang_id:0x%04X [Unknown language])" % (
                                        str(dir_type.name), str(nameID.name), language.id)
                                res_strings = ResultSection("PE: STRINGS - %s" % comment)
                                for idx in range(len(strings)):
                                    # noinspection PyBroadException
                                    try:
                                        tag_value = strings[idx][1]

                                        # The following line crash chardet if a
                                        # UPX packed file as packed the resources...
                                        chardet.detect(tag_value)  # TODO: Find a better way to do this

                                        tag_value = tag_value.replace('\r', ' ').replace('\n', ' ')
                                        if strings[idx][0] is not None:
                                            res_strings.add_line(f"{strings[idx][0]}: {tag_value}")
                                        else:
                                            res_strings.add_line(tag_value)

                                        res_strings.add_tag('file.string.extracted', tag_value)

                                        success = True
                                    except Exception:
                                        pass
                                if success:
                                    self.file_res.add_section(res_strings)
                else:
                    pass

        except AttributeError as e:
            self.log.debug("\t Error parsing output: " + repr(e))

        except Exception as e:
            self.log.exception(e)

        # print slack space if it exists
        if (self.print_slack and self.filesize_from_peheader > 0 and (
                len(self.pe_file.__data__) > self.filesize_from_peheader)):
            length_to_display = PEFILE_SLACK_LENGTH_TO_DISPLAY
            if length_to_display > 0:
                length_display_str = ""
                slack_size = len(self.pe_file.__data__) - self.filesize_from_peheader
                if slack_size > length_to_display:
                    length_display_str = "- displaying first %d bytes" % length_to_display
                pe_slack_space_res = ResultSection("PE: SLACK SPACE (The file contents after the PE file size ends) "
                                                   "[%d bytes] %s" % (
                                                       len(self.pe_file.__data__) - self.filesize_from_peheader,
                                                       length_display_str),
                                                   body_format=BODY_FORMAT['MEMORY_DUMP'])
                pe_slack_space_res.add_line(hexdump(
                    self.pe_file.__data__[self.filesize_from_peheader:self.filesize_from_peheader + length_to_display]))
                self.file_res.add_section(pe_slack_space_res)

    def _init_section_list(self):
        # Lazy init
        if self._sect_list is None:
            self._sect_list = []
            try:
                for section in self.pe_file.sections:
                    zero_idx = section.Name.find(chr(0x0).encode())
                    if not zero_idx == -1:
                        sname = section.Name[:zero_idx]
                    else:
                        sname = safe_str(section.Name)
                    entropy = section.get_entropy()
                    self._sect_list.append((sname, section, section.get_hash_md5(), entropy))
            except AttributeError:
                pass

    def get_export_module_name(self):

        try:
            section = self.pe_file.get_section_by_rva(self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.Name)
            offset = section.get_offset_from_rva(self.pe_file.DIRECTORY_ENTRY_EXPORT.struct.Name)
            self.pe_file.ModuleName = self.pe_file.__data__[offset:offset +
                                                            self.pe_file.__data__[offset:].find(chr(0).encode())]
        except AttributeError:
            pass

    def get_import_hash(self):
        try:
            if (self.import_hash is None and
                    len(self.pe_file.DIRECTORY_ENTRY_IMPORT) > 0):
                sorted_import_list = []
                for entry in self.pe_file.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name is None:
                            sorted_import_list.append(str(imp.ordinal).encode())
                        else:
                            sorted_import_list.append(imp.name)

                sorted_import_list.sort()
                self.import_hash = hashlib.sha1(b" ".join(sorted_import_list)).hexdigest()
        except AttributeError:
            pass

        return self.import_hash

    def execute(self, request):
        request.result = Result()
        self.file_res = request.result
        self.path = request.file_path
        filename = os.path.basename(self.path)
        self.request = request

        self.pe_file = None
        self._sect_list = None
        self.entropy_warning = False
        self.unexpected_sname = []
        self.import_hash = None
        self.filename = filename
        self.print_slack = True
        self.patch_section = None
        self.filesize_from_peheader = -1

        with open(self.path, 'rb') as f:
            file_content = f.read()

        try:
            self.impfuzzy = pyimpfuzzy.pefileEx(data=file_content)
            self.pe_file = pefile.PE(data=file_content)
        except pefile.PEFormatError as e:
            if e.value != "DOS Header magic not found.":
                res_load_failed = ResultSection(f"WARNING: this file looks like a PE but failed "
                                                f"loading inside PE file. [{e.value}]")
                res_load_failed.set_heuristic(6)
                self.file_res.add_section(res_load_failed)
            else:
                self.log.debug("DOS Header magic not found. This indicates that the file submitted is not a PE File.")
            self.log.debug(e)

        if self.pe_file is not None:
            self.get_export_module_name()
            self.get_pe_info(G_LCID)
            self.get_signature_information(BytesIO(file_content))
            self.get_api_vector()

    def get_api_vector(self):
        # We need to do a bit of manipulation on the list of API calls to normalize to
        # the format that apiscout/apivector expects, notably (from apivector blog post)
        # We drop the string type, i.e. A or W if applicable
        # We ignore MSVCRT versions, i.e. msvcrt80.dll!time becoming msvcrt.dll!time
        apilist = (x.replace(".", "!").rstrip("aw") for x in self.impfuzzy.calc_impfuzzy(return_list=True))
        apilist2 = [re.sub("msvcrt[0-9]+!", "msvcrt!", x) for x in apilist]
        apivector = self.apivector.getApiVectorFromApiList(apilist2)

        api_vectors_res = ResultSection("API Vectors")
        # apivector is given as something like:
        # {'user_list': {'in_api_vector': 2,
        #                'num_unique_apis': 2,
        #                'percentage': 100.0,
        #                'vector': 'A40BA93QA36'}}
        api_vectors_res.add_line(f"in_api_vector: {apivector.get('user_list', {}).get('in_api_vector', 0)}")
        api_vectors_res.add_line(f"num_unique_apis: {apivector.get('user_list', {}).get('num_unique_apis', 0)}")
        api_vectors_res.add_line(f"vector: {apivector.get('user_list', {}).get('vector', '')}")

        # For the sake of tagging, we'll just make it a colon separated string of
        # in_api_vector:num_unique_apis:vector
        # (omitting the percentage, since that's easy to recalculate)
        apivector_str = "%d:%d:%s" % (
            apivector.get("user_list", {}).get("in_api_vector", 0),
            apivector.get("user_list", {}).get("num_unique_apis", 0),
            apivector.get("user_list", {}).get("vector", "")
        )
        api_vectors_res.add_tag("file.pe.api_vector", apivector_str)
        self.file_res.add_section(api_vectors_res)

    def get_signature_information(self, file_handle):
        # noinspection PyBroadException
        try:
            res = ResultSection("Signature Information")

            # first, let's try parsing the file
            # noinspection PyBroadException
            try:
                s_data = signed_pe.SignedPEFile(file_handle)
            except Exception:
                self.log.error("Error parsing. May not be a valid PE? Traceback: %s" % traceback.format_exc())
                return

            # Now try checking for verification
            try:
                s_data.verify()

                # signature is verified
                res.add_subsection(ResultSection("This file is signed", heuristic=Heuristic(2)))
            except SignedPEParseError as e:
                if str(e) == "The PE file does not contain a certificate table.":
                    res.add_subsection(ResultSection("No file signature data found"))

                else:
                    res.add_subsection("Unknown exception. Traceback: %s" % traceback.format_exc())
                self.file_res.add_section(res)
                return
            except AuthenticodeVerificationError as e:
                if str(e) == "The expected hash does not match the digest in SpcInfo":
                    # This sig has been copied from another program
                    res.add_subsection(ResultSection("The signature does not match the program data",
                                                     heuristic=Heuristic(1)))
                else:
                    res.add_subsection(ResultSection(f"Unknown authenticode exception. "
                                                     f"Traceback: {traceback.format_exc()}"))
                self.file_res.add_section(res)
                return
            except VerificationError as e:
                ex = str(e)
                if ex.startswith("Chain verification from"):
                    # probably self signed, but maybe we just don't have the root CA
                    flatten = lambda l: [item for sublist in l for item in sublist]
                    cert_list = flatten([x.certificates for x in s_data.signed_datas])

                    # Check to see if all of the issuers are the same. If they are, then this is likely self signed
                    # Otherwise, it *may* still be still signed, *or* just signed by a root CA we don't know about
                    if len(cert_list) >= 2:
                        if "The X.509 certificate provided is self-signed" in ex:
                            res.add_subsection(
                                ResultSection("File is self-signed (signing cert signed by itself)",
                                              heuristic=Heuristic(6)))
                        elif all([cert_list[i].issuer == cert_list[i + 1].issuer for i in range(len(cert_list) - 1)]):
                            res.add_subsection(ResultSection("File is self-signed, all certificate issuers match",
                                                             heuristic=Heuristic(3)))
                        else:
                            res.add_subsection(ResultSection("Possibly self signed. "
                                                             "Could not identify a chain of "
                                                             "trust back to a known root CA, but certificates "
                                                             "presented were issued by different issuers",
                                                             heuristic=Heuristic(5)))
                    else:
                        res.add_subsection(
                            ResultSection("This is probably an error. Less than 2 certificates were found",
                                          heuristic=Heuristic(8)))
                else:
                    res.add_subsection(ResultSection("Unknown exception. Traceback: %s" % traceback.format_exc()))
                self.file_res.add_section(res)
                return

            # Now try to get certificate and signature data
            sig_datas = [x for x in s_data.signed_datas]

            if len(sig_datas) > 0:
                # Now extract certificate data from the sig
                for s in sig_datas:
                    signer_res = ResultSection("Signer Information")
                    res.add_subsection(signer_res)

                    signer_res.add_lines([f"Serial No: {str(s.signer_info.serial_number)}",
                                          f"Issuer: {s.signer_info.issuer_dn}"])

                    # Extract signer info. This is probably the most useful?
                    signer_res.add_tag("cert.serial_no", str(s.signer_info.serial_number))
                    signer_res.add_tag("cert.issuer", s.signer_info.issuer_dn)

                    # Get cert used for signing, then add valid from/to info
                    for cert in [x for x in s.certificates if x.serial_number == s.signer_info.serial_number]:
                        signer_res.add_lines([f"Subject: {cert.subject_dn}",
                                              f"Valid From: {cert.valid_from.isoformat()}",
                                              f"Valid To: {cert.valid_to.isoformat()}",
                                              f"Thumbprint: {hashlib.sha1(cert.to_der).hexdigest()}"])

                        signer_res.add_tag("cert.subject", cert.subject_dn)
                        signer_res.add_tag("cert.valid.start", cert.valid_from.isoformat())
                        signer_res.add_tag("cert.valid.end", cert.valid_to.isoformat())

                        # The thumbprints generated this way match what VirusTotal reports for 'certificate thumbprints'
                        signer_res.add_tag("cert.thumbprint", hashlib.sha1(cert.to_der).hexdigest())
                        break

                    for cert in s.certificates:
                        cert_res = ResultSection("Certificate Information")

                        # probably not worth doing tags for all this info?
                        cert_res.add_lines(["Version: %d" % cert.version,
                                            "Serial No: %d" % cert.serial_number,
                                            "Thumbprint: %s" % hashlib.sha1(cert.to_der).hexdigest(),
                                            "Issuer: %s" % cert.issuer_dn,
                                            "Subject: %s" % cert.subject_dn,
                                            "Valid From: %s" % cert.valid_from.isoformat(),
                                            "Valid To: %s" % cert.valid_to.isoformat()])

                        signer_res.add_subsection(cert_res)
        except Exception as e:
            res = None
            if isinstance(e, ParseError):
                cve20200601 = "SignerInfo.digestEncryptionAlgorithm: [0-9.]* is not acceptable as encryption algorithm"
                if re.match(cve20200601, str(e)):
                    res = ResultSection("Invalid Encryption Algorithm used for signature", heuristic=Heuristic(9))
                    res.add_lines(["The following exception was generated while trying to validate signature:",
                                   safe_str(str(e)),
                                   "This is usually a sign of someone tampering with "
                                   "the signature information.(Used by: CVE_2020_0601)"])
                    res.add_tag("attribution.exploit", "CVE_2020_0601")

            if not res:
                self.log.warning("Could not parse signature properly:\n" + traceback.format_exc())

                res = ResultSection("Invalid PE Signature detected", heuristic=Heuristic(1))
                res.add_lines(["The following exception was generated while trying to validate signature:",
                               safe_str(str(e))])

        self.file_res.add_section(res)
