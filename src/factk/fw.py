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
            epoll.register(fw[EPOLLEXCLUSIVE)
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

