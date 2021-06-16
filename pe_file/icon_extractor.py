import struct
from io import BytesIO
from PIL import Image


GRPICONDIRENTRY_format = ('GRPICONDIRENTRY',
        ('B,Width', 'B,Height','B,ColorCount','B,Reserved',
        'H,Planes','H,BitCount','I,BytesInRes','H,ID'))
GRPICONDIR_format = ('GRPICONDIR',
    ('H,Reserved', 'H,Type','H,Count'))

def get_icon(pe_file, icon_rsrcs, idx):
    
    # print(f' {icon_rsrcs.id} -- {len(icon_rsrcs.directory.entries)} -- {idx}')
    icon_id = icon_rsrcs.directory.entries[idx-1]
    icon_entry = icon_id.directory.entries[0]

    data_rva = icon_entry.data.struct.OffsetToData
    size = icon_entry.data.struct.Size
    data = pe_file.get_memory_mapped_image()[data_rva:data_rva+size]
    return data



def export_raw(pe_file, icon_rsrcs, entries, index = None):
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

    raw = export_raw(pe_file, icon_rsrcs, entries, index)
    return Image.open(BytesIO(raw))



