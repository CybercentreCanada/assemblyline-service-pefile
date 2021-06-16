import struct
from io import BytesIO
from PIL import Image
import pefile


GRPICONDIRENTRY_format = ('GRPICONDIRENTRY',
        ('B,Width', 'B,Height','B,ColorCount','B,Reserved',
        'H,Planes','H,BitCount','I,BytesInRes','H,ID'))
GRPICONDIR_format = ('GRPICONDIR',
    ('H,Reserved', 'H,Type','H,Count'))

def get_icon_group(pe_file: pefile.PE, data_entry : pefile.Structure) -> list:
    data_rva = data_entry.OffsetToData
    size = data_entry.Size
    data = pe_file.get_memory_mapped_image()[data_rva:data_rva+size]
    file_offset = pe_file.get_offset_from_rva(data_rva)

    grp_icon_dir = pefile.Structure(GRPICONDIR_format, file_offset=file_offset)
    grp_icon_dir.__unpack__(data)

    if grp_icon_dir.Reserved == 0 or grp_icon_dir.Type == 1:
        offset = grp_icon_dir.sizeof()
        entries = list()
        for idx in range(0, grp_icon_dir.Count):
            grp_icon = pefile.Structure(GRPICONDIRENTRY_format, file_offset=file_offset+offset)
            grp_icon.__unpack__(data[offset:])
            offset += grp_icon.sizeof()
            entries.append(grp_icon)

        return entries

    return None

def get_icon(pe_file, icon_rsrcs, idx):
    icon_id = icon_rsrcs.directory.entries[idx-1]
    icon_entry = icon_id.directory.entries[0]

    data_rva = icon_entry.data.struct.OffsetToData
    size = icon_entry.data.struct.Size
    data = pe_file.get_memory_mapped_image()[data_rva:data_rva+size]
    return data


def icon_export_raw(pe_file, icon_rsrcs, entries, index = None):
    if index is not None:
        entries = entries[index:index+1]

    ico = struct.pack('<HHH', 0, 1, len(entries))
    data_offset = None
    data = []
    info = []
    for grp_icon in entries:
        if data_offset is None:
            data_offset = len(ico) + ((grp_icon.sizeof()+2) * len(entries))

        nfo = grp_icon.__pack__()[:-2] + struct.pack('<L', data_offset)			
        info.append( nfo )

        raw_data = get_icon(pe_file, icon_rsrcs, grp_icon.ID)
        if not raw_data: continue

        data.append( raw_data )
        data_offset += len(raw_data)

    raw = ico + b''.join(info) + b''.join(data)
    return raw

def icon_export(pe_file, icon_rsrcs, entries, index = None):
    if icon_rsrcs is None:
        return None

    raw = icon_export_raw(pe_file, icon_rsrcs, entries, index)
    return Image.open(BytesIO(raw))



