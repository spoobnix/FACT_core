from abc import ABC
import .plugins as Plugin

class AbstractPlugin(ABC):
    #TODO abstract methods
    def __prepare__(mcs, bases: *Plugin):
        try:
            mcs.register(*bases)
        except as exc:
            print('failing gracefully')
            raise exc
        finally:
            return True

class BasePlugin(AbstractPlugin):

    def __new__(self, *bases, **kwargs):
        self.DEPS = bases
        for _, element in enumerate(kwargs):
            setattr(self, str(_), element)

#      def _sync_view(self, plugin_path):
#       if plugin_path:
#           view_source = self._get_view_file_path(plugin_path)
#           if view_source is not None:
#               view = get_binary_from_file(view_source)
#               with ConnectTo(ViewUpdater, self.config) as connection:
#                   connection.update_view(self.NAME, view)

#   def _get_view_file_path(self, plugin_path):
#       plugin_path = get_parent_dir(get_dir_of_file(plugin_path))
#       view_files = get_files_in_dir(os.path.join(plugin_path, 'view'))
#       if len(view_files) < 1:
#           logging.debug('{}: No view available! Generic view will be used.'.format(self.NAME))
#           return None
#       if len(view_files) > 1:
#           logging.warning('{}: Plug-in provides more than one view! \'{}\' is used!'.format(self.NAME, view_files[0]))
#       return view_files[0]

#   def register_plugin(self):
#       self.plugin_administrator.register_plugin(self.NAME, self)


