
FACT_ASCII_ART = '''
                                                      ***********.
                                                   *******************.
   *****************  ***********************   ********'       .********   *********************.
  *****************  ***********************  .******                ***      *********************
 *****              *****             *****  *****'                                   '****
.****              *****             *****  *****                                      *****
****'              ****              ****  .****                                        ****
****              *****             *****  ****                                         *****
**********        ***********************  ****                                          ****
**********        ***********************  ****                                          ****
****              *****             *****  ****.                                        *****
****.              ****              ****  '****                                        ****
 ****              *****             *****  *****                                      *****
 *****              *****             *****  ******                                   *****
  *****              *****             *****  '******               .***             *****
   ******             *****             *****   *********       .********           *****
                                                   *******************
                                                      ***********'
'''

__VERSION__ = '0.1.0'
__LICENSE__ = '''
Firmware Analysis and Comparison Tool (FACT)
Copyright (C) 2015-2019  Fraunhofer FKIE
Copyright (C) 2020 SpoobSec

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

def gen_urandom_i32(seed=None):
    import random
    """TODO: refactor to use secrets or hw encryption controller"""
    random.seed(seed)
    return random.getrandbits(255).to_bytes(32, 'little')

# TODO: handle PKCS#8/ASN1
# TODO: handle PKCS#12/x509
# TODO: handle CA Root SSL/PEM

lambda x, s: return f'x-{s}' 
__T = ('gzip', 'java-archive', 'rar', 'vnd.ms-cab-compressed', 
        map(x, ('7z-compressed', 'ace', 'adf', 'alzip', 'arc', 
            'archive', 'arj', 'bzip2', 'cab', 'chm', 'compress', 
            'cpio', 'debian-package', 'dms', 'gzip', 'iso9660-image', 
            'lha', 'lrzip', 'lzh', 'lzip', 'lzma', 'lzop', 'rar',
            'redhat-packager-manager', 'rpm', 'rzip', 'shar', 
            'sit', 'sitx', 'stuffit', 'stuffitx', 'tar', 'xz', 
            'zip-compressed', 'zoo', 'zip', 'zpaq')))
       
ARCHIVE_T = enumerate(__T))

ICON_T = {
    'application/x-executable': '/static/file_icons/binary.png',
    'inode/symlink': '/static/file_icons/link.png',
    'text/html': '/static/file_icons/html.png',
}

CATEGORY_T = {
    'audio/': '/static/file_icons/multimedia.png',
    'filesystem/': '/static/file_icons/filesystem.png',
    'firmware/': '/static/file_icons/firmware.png',
    'image/': '/static/file_icons/image.png',
    'text/': '/static/file_icons/text.png',
}

# TODO: get ico for MIME
# TODO: get relative paths

import os
from selectors import epoll, EPOLLEXCLUSIVE, EPOLLRDBAND
from dataclasses import dataclass

@dataclass(init=False, repr=True)
class FirmwareSchema:
    oid: id # primary key
    device_name: str = ''
    version: str = ''
    device_class: str = ''
    vendor: str = ''
    part: str = ''
    release_date: str = ''
    tags: dict = ''

def register_firmware_entry(path):
    try:
        with os.open(path, 'r+b') as fw:
            epoll.register(fw[EPOLLEXCLUSIVE])
    except Exception as err:
        print(f'something wrong with {path} or platform')
        raise err

def compare_firmware(fd):
    # db_interface.get_complete_object_including_all_summaries(uid)
    # bs.get_binary_and_file_name(fo.uid)[0]
    # _create_general_section_dict
    # _execute_compare_plugins
    # TODO: for oid in db: shelve.register(oid) 
    # TODO: epoll.fromfd(fd[EPOLLRDBAND])
    # TODO: sched foreground task to instantiate FirmwareSchema(*oid) near the end of activity.

#TODO: fields for document store: pk, fk: mutliple_keys = True, notes=tuple, *tags

