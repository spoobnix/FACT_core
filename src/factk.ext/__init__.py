import logging
import os

from common_helper_files import get_binary_from_file, get_dir_of_file, get_files_in_dir

from helperFunctions.database import ConnectTo
from helperFunctions.fileSystem import get_parent_dir
from storage.db_interface_view_sync import ViewUpdater


class BasePlugin():
    NAME = 'base'
    DEPENDENCIES = []

    def __init__(self, plugin_administrator, config=None, plugin_path=None):
        self.plugin_administrator = plugin_administrator
        self.config = config
        self._sync_view(plugin_path)

    def _sync_view(self, plugin_path):
        if plugin_path:
            view_source = self._get_view_file_path(plugin_path)
            if view_source is not None:
                view = get_binary_from_file(view_source)
                with ConnectTo(ViewUpdater, self.config) as connection:
                    connection.update_view(self.NAME, view)

    def _get_view_file_path(self, plugin_path):
        plugin_path = get_parent_dir(get_dir_of_file(plugin_path))
        view_files = get_files_in_dir(os.path.join(plugin_path, 'view'))
        if len(view_files) < 1:
            logging.debug('{}: No view available! Generic view will be used.'.format(self.NAME))
            return None
        if len(view_files) > 1:
            logging.warning('{}: Plug-in provides more than one view! \'{}\' is used!'.format(self.NAME, view_files[0]))
        return view_files[0]

    def register_plugin(self):
        self.plugin_administrator.register_plugin(self.NAME, self)
import logging
from pathlib import Path

from common_helper_files import get_dirs_in_dir
from pluginbase import PluginBase

from helperFunctions.fileSystem import get_src_dir


def import_plugins(plugin_mount, plugin_base_dir):
    plugin_base = PluginBase(package=plugin_mount)
    plugin_src_dirs = _get_plugin_src_dirs(plugin_base_dir)
    return plugin_base.make_plugin_source(searchpath=plugin_src_dirs)


def _get_plugin_src_dirs(base_dir):
    plug_in_base_path = Path(get_src_dir(), base_dir)
    plugin_dirs = get_dirs_in_dir(str(plug_in_base_path))
    plugins = []
    for plugin_path in plugin_dirs:
        plugin_code_dir = Path(plugin_path, 'code')
        if plugin_code_dir.is_dir():
            plugins.append(str(plugin_code_dir))
        else:
            logging.warning('Plugin has no code directory: {}'.format(plugin_path))
    return plugins
