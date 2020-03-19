import logging
from flask import render_template, request
import importlib
import inspect
import pkgutil
from time import time
import json
import random
from typing import List
import json
from tempfile import TemporaryDirectory
from time import sleep
import json
import logging
from datetime import datetime

from dateutil.relativedelta import relativedelta
from flask import redirect, render_template, request, url_for
from flask_paginate import Pagination

from helperFunctions.config import read_list_from_config
from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import make_unicode_string
from helperFunctions.mongo_task_conversion import get_file_name_and_binary_from_request
from helperFunctions.web_interface import apply_filters_to_query, filter_out_illegal_characters
from helperFunctions.yara_binary_search import get_yara_error, is_valid_yara_rule_file
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


import requests
from flask import make_response, redirect, render_template, request

from helperFunctions.database import ConnectTo
from helperFunctions.mongo_task_conversion import (
    check_for_errors, convert_analysis_task_to_fw_obj, create_analysis_task
)
from helperFunctions.pdf import build_pdf_report
from helperFunctions.web_interface import get_radare_endpoint
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


from common_helper_filter.time import time_format
from flask import render_template

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import none_to_none
from helperFunctions.hash import get_md5
from helperFunctions.uid import is_list_of_uids
from helperFunctions.web_interface import split_virtual_path, virtual_path_element_to_span
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface import filter as flt


from flask import redirect, render_template, request, url_for
from flask_security import login_required

from helperFunctions.database import ConnectTo
from statistic.update import StatisticUpdater
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


from flask_restful import Resource
from helperFunctions.fileSystem import get_src_dir
from web_interface.components.component_base import ComponentBase

ROUTES_MODULE_NAME = 'routes'
PLUGIN_CATEGORIES = ['analysis', 'compare']
PLUGIN_DIR = '{}/plugins'.format(get_src_dir())


from helperFunctions.database import ConnectTo
from helperFunctions.web_interface import apply_filters_to_query
from intercom.front_end_binding import InterComFrontEndBinding
from statistic.update import StatisticUpdater
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_statistic import StatisticDbViewer
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


from contextlib import contextmanager

from flask import render_template, request, flash, redirect, url_for
from flask_security import current_user
from sqlalchemy.exc import SQLAlchemyError

from helperFunctions.web_interface import password_is_legal
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES, ROLES


from contextlib import suppress

from flask import redirect, render_template, render_template_string, request, session, url_for
from flask_paginate import Pagination

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import (
    convert_compare_id_to_list, convert_uid_list_to_compare_id, normalize_compare_id
)
from helperFunctions.web_interface import get_template_as_string
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from storage.db_interface_view_sync import ViewReader
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from typing import List

from common_helper_files import human_readable_file_size
from flask import jsonify, render_template

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import none_to_none
from helperFunctions.file_tree import FileTreeNode, get_correct_icon_for_mime, remove_virtual_path_from_root
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.filter import bytes_to_str_filter, encode_base64_filter
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES
import json
import os

from common_helper_files import get_binary_from_file
from flask import flash, render_template, render_template_string, request
from flask_login.utils import current_user

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import none_to_none
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.mongo_task_conversion import (
    check_for_errors, convert_analysis_task_to_fw_obj, create_re_analyze_task
)
from helperFunctions.web_interface import get_template_as_string, overwrite_default_plugins
from intercom.front_end_binding import InterComFrontEndBinding
from objects.firmware import Firmware
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_view_sync import ViewReader
from web_interface.components.compare_routes import get_comparison_uid_list_from_session
from web_interface.components.component_base import ComponentBase
from web_interface.security.authentication import user_has_privilege
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES



class AjaxRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/ajax_tree/<uid>/<root_uid>', '/ajax_tree/<uid>/<root_uid>', self._ajax_get_tree_children)
        self._app.add_url_rule('/ajax_root/<uid>/<root_uid>', 'ajax_root/<uid>/<root_uid>', self._ajax_get_tree_root)
        self._app.add_url_rule('/compare/ajax_tree/<compare_id>/<root_uid>/<uid>', 'compare/ajax_tree/<compare_id>/<root_uid>/<uid>',
                               self._ajax_get_tree_children)
        self._app.add_url_rule('/compare/ajax_common_files/<compare_id>/<feature_id>/', 'compare/ajax_common_files/<compare_id>/<feature_id>/',
                               self._ajax_get_common_files_for_compare)
        self._app.add_url_rule('/ajax_get_binary/<mime_type>/<uid>', 'ajax_get_binary/<type>/<uid>', self._ajax_get_binary)
        self._app.add_url_rule('/ajax_get_summary/<uid>/<selected_analysis>', 'ajax_get_summary/<uid>/<selected_analysis>', self._ajax_get_summary)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_tree_children(self, uid, root_uid=None, compare_id=None):
        root_uid, compare_id = none_to_none(root_uid), none_to_none(compare_id)
        exclusive_files = self._get_exclusive_files(compare_id, root_uid)
        tree = self._generate_file_tree(root_uid, uid, exclusive_files)
        children = [
            self._generate_jstree_node(child_node)
            for child_node in tree.get_list_of_child_nodes()
        ]
        return jsonify(children)

    def _get_exclusive_files(self, compare_id, root_uid):
        if compare_id:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                return sc.get_exclusive_files(compare_id, root_uid)
        return None

    def _generate_file_tree(self, root_uid: str, uid: str, whitelist: List[str]) -> FileTreeNode:
        root = FileTreeNode(None)
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            child_uids = [
                child_uid
                for child_uid in sc.get_specific_fields_of_db_entry(uid, {'files_included': 1})['files_included']
                if whitelist is None or child_uid in whitelist
            ]
            for node in sc.generate_file_tree_nodes_for_uid_list(child_uids, root_uid or uid, whitelist):
                root.add_child_node(node)
        return root

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_tree_root(self, uid, root_uid):
        root = list()
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            for node in sc.generate_file_tree_level(uid, root_uid):  # only a single item in this 'iterable'
                root = [self._generate_jstree_node(node)]
        root = remove_virtual_path_from_root(root)
        return jsonify(root)

    @staticmethod
    def _get_jstree_node_contents(text, a_attr, li_attr, icon):
        return {
            'text': text,
            'a_attr': {'href': a_attr},
            'li_attr': {'href': li_attr},
            'icon': icon
        }

    def _get_virtual_jstree_node_contents(self, node):
        return self._get_jstree_node_contents('{}'.format(node.name), '#', '#', '/static/file_icons/folder.png')

    def _get_not_analyzed_jstree_node_contents(self, node):
        return self._get_jstree_node_contents(
            '{}'.format(node.name), '/analysis/{}/ro/{}'.format(node.uid, node.root_uid), '/analysis/{}/ro/{}'.format(node.uid, node.root_uid), '/static/file_icons/not_analyzed.png'
        )

    def _get_analyzed_jstree_node_contents(self, node):
        result = self._get_jstree_node_contents(
            '<b>{}</b> (<span style="color:gray;">{}</span>)'.format(node.name, human_readable_file_size(node.size)),
            '/analysis/{}/ro/{}'.format(node.uid, node.root_uid), '/analysis/{}/ro/{}'.format(node.uid, node.root_uid), get_correct_icon_for_mime(node.type)
        )
        result['data'] = {'uid': node.uid}
        return result

    def _get_jstree_child_nodes(self, node):
        child_nodes = node.get_list_of_child_nodes()
        if not child_nodes:
            return True
        result = []
        for child in child_nodes:
            result_child = self._generate_jstree_node(child)
            if result_child is not None:
                result.append(result_child)
        return result

    def _generate_jstree_node(self, node):
        '''
        converts a file tree node to a json dict that can be rendered by jstree
        :param node: the file tree node
        :return: a json-compatible dict containing the jstree data
        '''
        if node.virtual:
            result = self._get_virtual_jstree_node_contents(node)
        elif node.not_analyzed:
            result = self._get_not_analyzed_jstree_node_contents(node)
        else:
            result = self._get_analyzed_jstree_node_contents(node)
        if node.has_children:
            result['children'] = self._get_jstree_child_nodes(node)
        return result

    @roles_accepted(*PRIVILEGES['compare'])
    def _ajax_get_common_files_for_compare(self, compare_id, feature_id):
        with ConnectTo(CompareDbInterface, self._config) as sc:
            result = sc.get_compare_result(compare_id)
        feature, matching_uid = feature_id.split('___')
        uid_list = result['plugins']['File_Coverage'][feature][matching_uid]
        return self._get_nice_uid_list_html(uid_list, root_uid=self._get_root_uid(matching_uid, compare_id))

    @staticmethod
    def _get_root_uid(candidate, compare_id):
        # feature_id contains a uid in individual case, in all case simply take first uid from compare
        if candidate != 'all':
            return candidate
        return compare_id.split(';')[0]

    def _get_nice_uid_list_html(self, input_data, root_uid):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            included_files = sc.get_data_for_nice_list(input_data, None)
        number_of_unanalyzed_files = len(input_data) - len(included_files)
        return render_template(
            'generic_view/nice_fo_list.html',
            fo_list=included_files,
            number_of_unanalyzed_files=number_of_unanalyzed_files,
            omit_collapse=True,
            root_uid=root_uid
        )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_binary(self, mime_type, uid):
        mime_type = mime_type.replace('_', '/')
        div = '<div style="display: block; border: 1px solid; border-color: #dddddd; padding: 5px; text-align: center">'
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            binary = sc.get_binary_and_filename(uid)[0]
        if 'text/' in mime_type:
            return '<pre style="white-space: pre-wrap">{}</pre>'.format(html.escape(bytes_to_str_filter(binary)))
        if 'image/' in mime_type:
            return '{}<img src="data:image/{} ;base64,{}" style="max-width:100%"></div>'.format(div, mime_type[6:], encode_base64_filter(binary))
        return None

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_summary(self, uid, selected_analysis):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            firmware = sc.get_object(uid, analysis_filter=selected_analysis)
            summary_of_included_files = sc.get_summary(firmware, selected_analysis)
        return render_template('summary.html', summary_of_included_files=summary_of_included_files, root_uid=uid)

def get_analysis_view(view_name):
    view_path = os.path.join(get_src_dir(), 'web_interface/templates/analysis_plugins/{}.html'.format(view_name))
    return get_binary_from_file(view_path).decode('utf-8')


class AnalysisRoutes(ComponentBase):

    analysis_generic_view = get_analysis_view('generic')
    analysis_unpacker_view = get_analysis_view('unpacker')

    def _init_component(self):
        self._app.add_url_rule('/update-analysis/<uid>', 'update-analysis/<uid>', self._update_analysis, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>', 'analysis/<uid>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>/ro/<root_uid>', '/analysis/<uid>/ro/<root_uid>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>/<selected_analysis>', '/analysis/<uid>/<selected_analysis>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>/<selected_analysis>/ro/<root_uid>', '/analysis/<uid>/<selected_analysis>/<root_uid>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/re-do_analysis/<uid>', '/admin/re-do_analysis/<uid>', self._re_do_analysis, methods=['GET', 'POST'])

    @staticmethod
    def _get_firmware_ids_including_this_file(fo):
        if isinstance(fo, Firmware):
            return None
        return list(fo.get_virtual_file_paths().keys())

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _show_analysis_results(self, uid, selected_analysis=None, root_uid=None):
        if request.method == 'POST':
            self._start_single_file_analysis(uid)

        other_versions = None
        with ConnectTo(CompareDbInterface, self._config) as db_service:
            all_comparisons = db_service.page_compare_results()
            known_comparisons = [comparison for comparison in all_comparisons if uid in comparison[0]]
        analysis_filter = [selected_analysis] if selected_analysis else []
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            file_obj = sc.get_object(uid, analysis_filter=analysis_filter)
            if not file_obj:
                return render_template('uid_not_found.html', uid=uid)
            if isinstance(file_obj, Firmware):
                root_uid = file_obj.uid
                other_versions = sc.get_other_versions_of_firmware(file_obj)
            included_fo_analysis_complete = not sc.all_uids_found_in_database(list(file_obj.files_included))
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            analysis_plugins = sc.get_available_analysis_plugins()
        return render_template_string(
            self._get_analysis_view(selected_analysis) if selected_analysis else get_template_as_string('show_analysis.html'),
            uid=uid,
            firmware=file_obj,
            selected_analysis=selected_analysis,
            all_analyzed_flag=included_fo_analysis_complete,
            root_uid=none_to_none(root_uid),
            firmware_including_this_fo=self._get_firmware_ids_including_this_file(file_obj),
            analysis_plugin_dict=analysis_plugins,
            other_versions=other_versions,
            uids_for_comparison=get_comparison_uid_list_from_session(),
            user_has_admin_clearance=user_has_privilege(current_user, privilege='delete'),
            known_comparisons=known_comparisons,
            available_plugins=self._get_used_and_unused_plugins(
                file_obj.processed_analysis,
                [x for x in analysis_plugins.keys() if x != 'unpacker']
            )
        )

    def _start_single_file_analysis(self, uid):
        if user_has_privilege(current_user, privilege='submit_analysis'):
            with ConnectTo(FrontEndDbInterface, self._config) as database:
                file_object = database.get_object(uid)
            file_object.scheduled_analysis = request.form.getlist('analysis_systems')
            with ConnectTo(InterComFrontEndBinding, self._config) as intercom:
                intercom.add_single_file_task(file_object)
        else:
            flash('You have insufficient rights to add additional analyses')

    @staticmethod
    def _get_used_and_unused_plugins(processed_analysis: dict, all_plugins: list) -> dict:
        return {
            'unused': [x for x in all_plugins if x not in processed_analysis],
            'used': [x for x in all_plugins if x in processed_analysis]
        }

    def _get_analysis_view(self, selected_analysis):
        if selected_analysis == 'unpacker':
            return self.analysis_unpacker_view
        with ConnectTo(ViewReader, self._config) as vr:
            view = vr.get_view(selected_analysis)
        if view:
            return view.decode('utf-8')
        return self.analysis_generic_view

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    def _update_analysis(self, uid, re_do=False):
        error = {}
        if request.method == 'POST':
            analysis_task = create_re_analyze_task(request, uid=uid)
            error = check_for_errors(analysis_task)
            if not error:
                self._schedule_re_analysis_task(uid, analysis_task, re_do)
                return render_template('upload/upload_successful.html', uid=uid)

        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            old_firmware = sc.get_firmware(uid=uid, analysis_filter=[])
            if old_firmware is None:
                return render_template('uid_not_found.html', uid=uid)

            device_class_list = sc.get_device_class_list()
            vendor_list = sc.get_vendor_list()
            device_name_dict = sc.get_device_name_dict()

        device_class_list.remove(old_firmware.device_class)
        vendor_list.remove(old_firmware.vendor)
        device_name_dict[old_firmware.device_class][old_firmware.vendor].remove(old_firmware.device_name)

        previously_processed_plugins = list(old_firmware.processed_analysis.keys())
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            plugin_dict = overwrite_default_plugins(sc, previously_processed_plugins)

        title = 're-do analysis' if re_do else 'update analysis'

        return render_template(
            'upload/re-analyze.html',
            device_classes=device_class_list,
            vendors=vendor_list,
            error=error,
            device_names=json.dumps(device_name_dict, sort_keys=True),
            firmware=old_firmware,
            analysis_plugin_dict=plugin_dict,
            title=title
        )

    def _schedule_re_analysis_task(self, uid, analysis_task, re_do):
        fw = convert_analysis_task_to_fw_obj(analysis_task)
        if re_do:
            with ConnectTo(AdminDbInterface, self._config) as sc:
                sc.delete_firmware(uid, delete_root_file=False)
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            sc.add_re_analyze_task(fw)

    @roles_accepted(*PRIVILEGES['delete'])
    def _re_do_analysis(self, uid):
        return self._update_analysis(uid, re_do=True)

class CompareRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/compare', '/compare/', self._app_show_start_compare)
        self._app.add_url_rule('/database/browse_compare', 'database/browse_compare', self._app_show_browse_compare)
        self._app.add_url_rule('/compare/<compare_id>', '/compare/<compare_id>', self._app_show_compare_result)
        self._app.add_url_rule('/comparison/add/<uid>', 'comparison/add/<uid>', self._add_to_compare_basket)
        self._app.add_url_rule('/comparison/remove/<analysis_uid>/<compare_uid>', 'comparison/remove/<analysis_uid>/<compare_uid>', self._remove_from_compare_basket)
        self._app.add_url_rule('/comparison/remove_all/<analysis_uid>', 'comparison/remove_all/<analysis_uid>', self._remove_all_from_compare_basket)

    @roles_accepted(*PRIVILEGES['compare'])
    def _app_show_compare_result(self, compare_id):
        compare_id = normalize_compare_id(compare_id)
        try:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                result = sc.get_compare_result(compare_id)
        except FactCompareException as exception:
            return render_template('compare/error.html', error=exception.get_message())
        if not result:
            return render_template('compare/wait.html', compare_id=compare_id)
        download_link = self._create_ida_download_if_existing(result, compare_id)
        uid_list = convert_compare_id_to_list(compare_id)
        plugin_views, plugins_without_view = self._get_compare_plugin_views(result)
        compare_view = self._get_compare_view(plugin_views)
        self._fill_in_empty_fields(result, compare_id)
        return render_template_string(
            compare_view,
            result=result,
            uid_list=uid_list,
            download_link=download_link,
            plugins_without_view=plugins_without_view
        )

    @staticmethod
    def _fill_in_empty_fields(result, compare_id):
        compare_uids = compare_id.split(';')
        for key in result['general']:
            for uid in compare_uids:
                if uid not in result['general'][key]:
                    result['general'][key][uid] = ''

    def _get_compare_plugin_views(self, compare_result):
        views, plugins_without_view = [], []
        with suppress(KeyError):
            used_plugins = list(compare_result['plugins'].keys())
            for plugin in used_plugins:
                with ConnectTo(ViewReader, self._config) as vr:
                    view = vr.get_view(plugin)
                if view:
                    views.append((plugin, view))
                else:
                    plugins_without_view.append(plugin)
        return views, plugins_without_view

    def _get_compare_view(self, plugin_views):
        compare_view = get_template_as_string('compare/compare.html')
        return self._add_plugin_views_to_compare_view(compare_view, plugin_views)

    def _add_plugin_views_to_compare_view(self, compare_view, plugin_views):
        key = '{# individual plugin views #}'
        insertion_index = compare_view.find(key)
        if insertion_index == -1:
            logging.error('compare view insertion point not found in compare template')
        else:
            insertion_index += len(key)
            for plugin, view in plugin_views:
                if_case = '{{% elif plugin == \'{}\' %}}'.format(plugin)
                view = '{}\n{}'.format(if_case, view.decode())
                compare_view = self._insert_plugin_into_view_at_index(view, compare_view, insertion_index)
        return compare_view

    @staticmethod
    def _insert_plugin_into_view_at_index(plugin, view, index):
        if index < 0:
            return view
        return view[:index] + plugin + view[index:]

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    def _app_show_start_compare(self):
        if 'uids_for_comparison' not in session or not isinstance(session['uids_for_comparison'], list) or len(session['uids_for_comparison']) < 2:
            return render_template('compare/error.html', error='No UIDs found for comparison')
        compare_id = convert_uid_list_to_compare_id(session['uids_for_comparison'])
        session['uids_for_comparison'] = None
        redo = True if request.args.get('force_recompare') else None

        with ConnectTo(CompareDbInterface, self._config) as sc:
            compare_exists = sc.compare_result_is_in_db(compare_id)
        if compare_exists and not redo:
            return redirect(url_for('/compare/<compare_id>', compare_id=compare_id))

        try:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                sc.check_objects_exist(compare_id)
        except FactCompareException as exception:
            return render_template('compare/error.html', error=exception.get_message())

        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            sc.add_compare_task(compare_id, force=redo)
        return render_template('compare/wait.html', compare_id=compare_id)

    @staticmethod
    def _create_ida_download_if_existing(result, compare_id):
        if isinstance(result, dict) and result.get('plugins', dict()).get('Ida_Diff_Highlighting', dict()).get('idb_binary'):
            return '/ida-download/{}'.format(compare_id)
        return None

    @roles_accepted(*PRIVILEGES['compare'])
    def _app_show_browse_compare(self):
        page, per_page = self._get_page_items()[0:2]
        try:
            with ConnectTo(CompareDbInterface, self._config) as db_service:
                compare_list = db_service.page_compare_results(skip=per_page * (page - 1), limit=per_page)
        except Exception as exception:
            error_message = 'Could not query database: {} {}'.format(type(exception), str(exception))
            logging.error(error_message)
            return render_template('error.html', message=error_message)

        with ConnectTo(CompareDbInterface, self._config) as connection:
            total = connection.get_total_number_of_results()

        pagination = self._get_pagination(page=page, per_page=per_page, total=total, record_name='compare results', )
        return render_template('database/compare_browse.html', compare_list=compare_list, page=page, per_page=per_page, pagination=pagination)

    @staticmethod
    def _get_pagination(**kwargs):
        kwargs.setdefault('record_name', 'records')
        return Pagination(css_framework='bootstrap3', link_size='sm', show_single_page=False,
                          format_total=True, format_number=True, **kwargs)

    def _get_page_items(self):
        page = int(request.args.get('page', 1))
        per_page = request.args.get('per_page')
        if not per_page:
            per_page = int(self._config['database']['results_per_page'])
        else:
            per_page = int(per_page)
        offset = (page - 1) * per_page
        return page, per_page, offset

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    def _add_to_compare_basket(self, uid):
        compare_uid_list = get_comparison_uid_list_from_session()
        compare_uid_list.append(uid)
        session.modified = True
        return redirect(url_for('analysis/<uid>', uid=uid))

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    def _remove_from_compare_basket(self, analysis_uid, compare_uid):
        compare_uid_list = get_comparison_uid_list_from_session()
        if compare_uid in compare_uid_list:
            session['uids_for_comparison'].remove(compare_uid)
            session.modified = True
        return redirect(url_for('analysis/<uid>', uid=analysis_uid))

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    def _remove_all_from_compare_basket(self, analysis_uid):
        compare_uid_list = get_comparison_uid_list_from_session()
        compare_uid_list.clear()
        session.modified = True
        return redirect(url_for('analysis/<uid>', uid=analysis_uid))


def get_comparison_uid_list_from_session():
    if 'uids_for_comparison' not in session or not isinstance(session['uids_for_comparison'], list):
        session['uids_for_comparison'] = []
    return session['uids_for_comparison']
# -*- coding: utf-8 -*-

from abc import ABCMeta, abstractmethod


class ComponentBase(metaclass=ABCMeta):
    def __init__(self, app, config, api=None):
        self._app = app
        self._config = config
        self._api = api

        self._init_component()

    @abstractmethod
    def _init_component(self):
        pass

class DatabaseRoutes(ComponentBase):

    def _init_component(self):
        self._app.add_url_rule('/database/browse', 'database/browse', self._app_show_browse_database)
        self._app.add_url_rule('/database/search', 'database/search', self._app_show_search_database, methods=['GET', 'POST'])
        self._app.add_url_rule('/database/advanced_search', 'database/advanced_search', self._app_show_advanced_search, methods=['GET', 'POST'])
        self._app.add_url_rule('/database/binary_search', 'database/binary_search', self._app_start_binary_search, methods=['GET', 'POST'])
        self._app.add_url_rule('/database/quick_search', 'database/quick_search', self._app_start_quick_search, methods=['GET'])
        self._app.add_url_rule('/database/database_binary_search_results.html', 'database/database_binary_search_results.html', self._app_show_binary_search_results)

    def _get_page_items(self):
        page = int(request.args.get('page', 1))
        per_page = request.args.get('per_page')
        if not per_page:
            per_page = int(self._config['database']['results_per_page'])
        else:
            per_page = int(per_page)
        offset = (page - 1) * per_page
        return page, per_page, offset

    @staticmethod
    def _get_pagination(**kwargs):
        kwargs.setdefault('record_name', 'records')
        return Pagination(css_framework='bootstrap3', link_size='sm', show_single_page=False,
                          format_total=True, format_number=True, **kwargs)

    @staticmethod
    def _add_date_to_query(query, date):
        try:
            start_date = datetime.strptime(date.replace('\'', ''), '%B %Y')
            end_date = start_date + relativedelta(months=1)
            date_query = {'release_date': {'$gte': start_date, '$lt': end_date}}
            if query == {}:
                query = date_query
            else:
                query = {'$and': [query, date_query]}
            return query
        except Exception:
            return query

    @roles_accepted(*PRIVILEGES['basic_search'])
    def _app_show_browse_database(self, query='{}', only_firmwares=False):
        page, per_page = self._get_page_items()[0:2]
        if request.args.get('query'):
            query = request.args.get('query')
        if request.args.get('only_firmwares'):
            only_firmwares = request.args.get('only_firmwares') == 'True'
        query = apply_filters_to_query(request, query)
        if request.args.get('date'):
            query = self._add_date_to_query(query, request.args.get('date'))
        try:
            firmware_list = self._search_database(query, skip=per_page * (page - 1), limit=per_page, only_firmwares=only_firmwares)
            if self._query_has_only_one_result(firmware_list, query):
                uid = firmware_list[0][0]
                return redirect(url_for('analysis/<uid>', uid=uid))
        except Exception as err:
            error_message = 'Could not query database: {} {}'.format(type(err), str(err))
            logging.error(error_message)
            return render_template('error.html', message=error_message)

        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            total = connection.get_number_of_total_matches(query, only_firmwares)
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()

        pagination = self._get_pagination(page=page, per_page=per_page, total=total, record_name='firmwares', )
        return render_template('database/database_browse.html', firmware_list=firmware_list, page=page, per_page=per_page, pagination=pagination,
                               device_classes=device_classes, vendors=vendors, current_class=str(request.args.get('device_class')), current_vendor=str(request.args.get('vendor')))

    @staticmethod
    def _query_has_only_one_result(result_list, query):
        return len(result_list) == 1 and query != '{}'

    def _search_database(self, query, skip=0, limit=0, only_firmwares=False):
        sorted_meta_list = list()
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            result = connection.generic_search(query, skip, limit, only_fo_parent_firmware=only_firmwares)
            if not isinstance(result, list):
                raise Exception(result)
            if not (query == '{}' or query == {}):
                firmware_list = [connection.firmwares.find_one(uid) or connection.file_objects.find_one(uid) for uid in result]
            else:  # if search query is empty: get only firmware objects
                firmware_list = [connection.firmwares.find_one(uid) for uid in result]
            sorted_meta_list = sorted(connection.get_meta_list(firmware_list), key=lambda x: x[1].lower())

        return sorted_meta_list

    def _build_search_query(self):
        query = {}
        if request.form['device_class_dropdown']:
            query.update({'device_class': request.form['device_class_dropdown']})
        for item in ['file_name', 'vendor', 'device_name', 'version', 'release_date']:
            if request.form[item]:
                query.update({item: {'$options': 'si', '$regex': request.form[item]}})
        if request.form['hash_value']:
            self._add_hash_query_to_query(query, request.form['hash_value'])
        return json.dumps(query)

    def _add_hash_query_to_query(self, query, value):
        hash_types = read_list_from_config(self._config, 'file_hashes', 'hashes')
        hash_query = [{'processed_analysis.file_hashes.{}'.format(hash_type): value} for hash_type in hash_types]
        query.update({'$or': hash_query})

    @roles_accepted(*PRIVILEGES['basic_search'])
    def _app_show_search_database(self):
        if request.method == 'POST':
            query = self._build_search_query()
            return redirect(url_for('database/browse', query=query))
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()
        return render_template('database/database_search.html', device_classes=device_classes, vendors=vendors)

    @roles_accepted(*PRIVILEGES['advanced_search'])
    def _app_show_advanced_search(self, error=None):
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            database_structure = connection.create_analysis_structure()
        if request.method == 'POST':
            try:
                query = json.loads(request.form['advanced_search'])  # check for syntax errors
                only_firmwares = request.form.get('only_firmwares') is not None
                if not isinstance(query, dict):
                    raise Exception('Error: search query invalid (wrong type)')
                return redirect(url_for('database/browse', query=json.dumps(query), only_firmwares=only_firmwares))
            except Exception as err:
                error = err
        return render_template('database/database_advanced_search.html', error=error, database_structure=database_structure)

    @roles_accepted(*PRIVILEGES['pattern_search'])
    def _app_start_binary_search(self):
        error = None
        if request.method == 'POST':
            yara_rule_file, firmware_uid = self._get_items_from_binary_search_request(request)
            if firmware_uid and not self._firmware_is_in_db(firmware_uid):
                error = 'Error: Firmware with UID {} not found in database'.format(repr(firmware_uid))
            elif yara_rule_file is not None:
                if is_valid_yara_rule_file(yara_rule_file):
                    with ConnectTo(InterComFrontEndBinding, self._config) as connection:
                        request_id = connection.add_binary_search_request(yara_rule_file, firmware_uid)
                    return redirect(url_for('database/database_binary_search_results.html', request_id=request_id))
                error = 'Error in YARA rules: {}'.format(get_yara_error(yara_rule_file))
            else:
                error = 'please select a file or enter rules in the text area'
        return render_template('database/database_binary_search.html', error=error)

    @staticmethod
    def _get_items_from_binary_search_request(req):
        yara_rule_file = None
        if 'file' in req.files and req.files['file']:
            _, yara_rule_file = get_file_name_and_binary_from_request(req)
        elif req.form['textarea']:
            yara_rule_file = req.form['textarea'].encode()
        firmware_uid = req.form.get('firmware_uid') if req.form.get('firmware_uid') else None
        return yara_rule_file, firmware_uid

    def _firmware_is_in_db(self, firmware_uid: str) -> bool:
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            return connection.is_firmware(firmware_uid)

    @roles_accepted(*PRIVILEGES['pattern_search'])
    def _app_show_binary_search_results(self):
        firmware_dict, error, yara_rules = None, None, None
        if request.args.get('request_id'):
            request_id = request.args.get('request_id')
            with ConnectTo(InterComFrontEndBinding, self._config) as connection:
                result, yara_rules = connection.get_binary_search_result(request_id)
            if isinstance(result, str):
                error = result
            elif result is not None:
                yara_rules = make_unicode_string(yara_rules[0])
                firmware_dict = self._build_firmware_dict_for_binary_search(result)
        else:
            error = 'No request ID found'
            request_id = None
        return render_template('database/database_binary_search_results.html', result=firmware_dict, error=error,
                               request_id=request_id, yara_rules=yara_rules)

    def _build_firmware_dict_for_binary_search(self, uid_dict):
        firmware_dict = {}
        for rule in uid_dict:
            with ConnectTo(FrontEndDbInterface, self._config) as connection:
                firmware_list = [
                    connection.firmwares.find_one(uid) or connection.file_objects.find_one(uid)
                    for uid in uid_dict[rule]
                ]
                firmware_dict[rule] = sorted(connection.get_meta_list(firmware_list))
        return firmware_dict

    @roles_accepted(*PRIVILEGES['basic_search'])
    def _app_start_quick_search(self):
        search_term = filter_out_illegal_characters(request.args.get('search_term'))
        if search_term is None:
            return render_template('error.html', message='Search string not found')
        query = {}
        self._add_hash_query_to_query(query, search_term)
        query['$or'].extend([
            {'device_name': {'$options': 'si', '$regex': search_term}},
            {'vendor': {'$options': 'si', '$regex': search_term}},
            {'file_name': {'$options': 'si', '$regex': search_term}}
        ])
        query = json.dumps(query)
        return redirect(url_for('database/browse', query=query))

class IORoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/upload', 'upload', self._app_upload, methods=['GET', 'POST'])
        self._app.add_url_rule('/download/<uid>', 'download/<uid>', self._app_download_binary)
        self._app.add_url_rule('/tar-download/<uid>', 'tar-download/<uid>', self._app_download_tar)
        self._app.add_url_rule('/ida-download/<compare_id>', 'ida-download/<compare_id>', self._download_ida_file)
        self._app.add_url_rule('/radare-view/<uid>', 'radare-view/<uid>', self._show_radare)
        self._app.add_url_rule('/pdf-download/<uid>', 'pdf-download/<uid>', self._download_pdf_report)

    # ---- upload
    @roles_accepted(*PRIVILEGES['submit_analysis'])
    def _app_upload(self):
        error = {}
        if request.method == 'POST':
            analysis_task = create_analysis_task(request)
            error = check_for_errors(analysis_task)
            if not error:
                fw = convert_analysis_task_to_fw_obj(analysis_task)
                with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                    sc.add_analysis_task(fw)
                return render_template('upload/upload_successful.html', uid=analysis_task['uid'])

        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            device_class_list = sc.get_device_class_list()
            vendor_list = sc.get_vendor_list()
            device_name_dict = sc.get_device_name_dict()
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            analysis_plugins = sc.get_available_analysis_plugins()
        return render_template(
            'upload/upload.html',
            device_classes=device_class_list, vendors=vendor_list, error=error,
            analysis_presets=list(self._config['default_plugins']),
            device_names=json.dumps(device_name_dict, sort_keys=True), analysis_plugin_dict=analysis_plugins
        )

        # ---- file download

    @roles_accepted(*PRIVILEGES['download'])
    def _app_download_binary(self, uid):
        return self._prepare_file_download(uid, packed=False)

    @roles_accepted(*PRIVILEGES['download'])
    def _app_download_tar(self, uid):
        return self._prepare_file_download(uid, packed=True)

    def _prepare_file_download(self, uid, packed=False):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            if packed:
                result = sc.get_repacked_binary_and_file_name(uid)
            else:
                result = sc.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, file_name = result
        response = make_response(binary)
        response.headers['Content-Disposition'] = 'attachment; filename={}'.format(file_name)
        return response

    @roles_accepted(*PRIVILEGES['download'])
    def _download_ida_file(self, compare_id):
        try:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                result = sc.get_compare_result(compare_id)
        except FactCompareException as exception:
            return render_template('error.html', message=exception.get_message())
        if result is None:
            return render_template('error.html', message='timeout')
        binary = result['plugins']['Ida_Diff_Highlighting']['idb_binary']
        response = make_response(binary)
        response.headers['Content-Disposition'] = 'attachment; filename={}.idb'.format(compare_id[:8])
        return response

    @roles_accepted(*PRIVILEGES['download'])
    def _show_radare(self, uid):
        host, post_path = get_radare_endpoint(self._config), '/v1/retrieve'
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            result = sc.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, _ = result
        try:
            response = requests.post('{}{}'.format(host, post_path), data=binary, verify=False)
            if response.status_code != 200:
                raise TimeoutError(response.text)
            target_link = '{}{}m/'.format(host, response.json()['endpoint'])
            sleep(1)
            return redirect(target_link)
        except Exception as exception:
            return render_template('error.html', message=str(exception))

    @roles_accepted(*PRIVILEGES['download'])
    def _download_pdf_report(self, uid):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)

        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            firmware = connection.get_complete_object_including_all_summaries(uid)

        try:
            with TemporaryDirectory() as folder:
                binary, pdf_path = build_pdf_report(firmware, folder)
        except RuntimeError as error:
            return render_template('error.html', message=str(error))

        response = make_response(binary)
        response.headers['Content-Disposition'] = 'attachment; filename={}'.format(pdf_path.name)

        return response

class FilterClass:
    '''
    This is WEB front end main class
    '''

    def __init__(self, app, program_version, config):
        self._program_version = program_version
        self._app = app
        self._config = config

        self._setup_filters()

    def _filter_print_program_version(self, *_):
        return '{}'.format(self._program_version)

    def _filter_replace_uid_with_file_name(self, input_data):
        tmp = input_data.__str__()
        uid_list = flt.get_all_uids_in_string(tmp)
        for item in uid_list:
            with ConnectTo(FrontEndDbInterface, self._config) as sc:
                file_name = sc.get_file_name(item)
            tmp = tmp.replace('>{}<'.format(item), '>{}<'.format(file_name))
        return tmp

    def _filter_replace_uid_with_hid(self, input_data, root_uid=None):
        tmp = str(input_data)
        if tmp == 'None':
            return ' '
        uid_list = flt.get_all_uids_in_string(tmp)
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            for item in uid_list:
                tmp = tmp.replace(item, sc.get_hid(item, root_uid=root_uid))
        return tmp

    def _filter_replace_comparison_uid_with_hid(self, input_data, root_uid=None):
        tmp = self._filter_replace_uid_with_hid(input_data, root_uid)
        res = tmp.split(';')
        return '  ||  '.join(res)

    def _filter_replace_uid_with_hid_link(self, input_data, root_uid=None):
        tmp = input_data.__str__()
        if tmp == 'None':
            return ' '
        uid_list = flt.get_all_uids_in_string(tmp)
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            for item in uid_list:
                tmp = tmp.replace(item, '<a href="/analysis/{}/ro/{}">{}</a>'.format(
                    item, root_uid, sc.get_hid(item, root_uid=root_uid)))
        return tmp

    def _filter_nice_uid_list(self, input_data, root_uid=None, selected_analysis=None):
        root_uid = none_to_none(root_uid)
        if not is_list_of_uids(input_data):
            return input_data
        show_id = str(random.randint(0, 999999))
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            included_files = sc.get_data_for_nice_list(input_data, root_uid)
        number_of_unanalyzed_files = len(input_data) - len(included_files)
        return render_template('generic_view/nice_fo_list.html', fo_list=included_files, u_show_id=show_id,
                               number_of_unanalyzed_files=number_of_unanalyzed_files,
                               root_uid=root_uid, selected_analysis=selected_analysis)

    def _nice_virtual_path_list(self, virtual_path_list: List[str]) -> List[str]:
        path_list = []
        for virtual_path in virtual_path_list:
            uid_list = split_virtual_path(virtual_path)
            components = [
                virtual_path_element_to_span(hid, uid, root_uid=uid_list[0])
                for hid, uid in zip(split_virtual_path(self._filter_replace_uid_with_hid(virtual_path)), uid_list)
            ]
            path_list.append(' '.join(components))
        return path_list

    @staticmethod
    def _render_firmware_detail_tabular_field(firmware_meta_data):
        return render_template('generic_view/firmware_detail_tabular_field.html', firmware=firmware_meta_data)

    def check_auth(self, _):
        return self._config.getboolean('ExpertSettings', 'authentication')

    def _setup_filters(self):
        self._app.jinja_env.add_extension('jinja2.ext.do')

        self._app.jinja_env.filters['auth_enabled'] = self.check_auth
        self._app.jinja_env.filters['base64_encode'] = flt.encode_base64_filter
        self._app.jinja_env.filters['bytes_to_str'] = flt.bytes_to_str_filter
        self._app.jinja_env.filters['data_to_chart'] = flt.data_to_chart
        self._app.jinja_env.filters['data_to_chart_limited'] = flt.data_to_chart_limited
        self._app.jinja_env.filters['data_to_chart_with_value_percentage_pairs'] = flt.data_to_chart_with_value_percentage_pairs
        self._app.jinja_env.filters['decompress'] = flt.decompress
        self._app.jinja_env.filters['dict_to_json'] = json.dumps
        self._app.jinja_env.filters['firmware_detail_tabular_field'] = self._render_firmware_detail_tabular_field
        self._app.jinja_env.filters['fix_cwe'] = flt.fix_cwe
        self._app.jinja_env.filters['format_string_list_with_offset'] = flt.filter_format_string_list_with_offset
        self._app.jinja_env.filters['get_canvas_height'] = flt.get_canvas_height
        self._app.jinja_env.filters['get_unique_keys_from_list_of_dicts'] = flt.get_unique_keys_from_list_of_dicts
        self._app.jinja_env.filters['infection_color'] = flt.infection_color
        self._app.jinja_env.filters['is_list'] = lambda item: isinstance(item, list)
        self._app.jinja_env.filters['json_dumps'] = json.dumps
        self._app.jinja_env.filters['list_to_line_break_string'] = flt.list_to_line_break_string
        self._app.jinja_env.filters['list_to_line_break_string_no_sort'] = flt.list_to_line_break_string_no_sort
        self._app.jinja_env.filters['md5_hash'] = get_md5
        self._app.jinja_env.filters['nice_generic'] = flt.generic_nice_representation
        self._app.jinja_env.filters['nice_list'] = flt.nice_list
        self._app.jinja_env.filters['nice_number'] = flt.nice_number_filter
        self._app.jinja_env.filters['nice_time'] = time_format
        self._app.jinja_env.filters['nice_uid_list'] = self._filter_nice_uid_list
        self._app.jinja_env.filters['nice_unix_time'] = flt.nice_unix_time
        self._app.jinja_env.filters['nice_virtual_path_list'] = self._nice_virtual_path_list
        self._app.jinja_env.filters['number_format'] = flt.byte_number_filter
        self._app.jinja_env.filters['print_program_version'] = self._filter_print_program_version
        self._app.jinja_env.filters['regex_meta'] = flt.comment_out_regex_meta_chars
        self._app.jinja_env.filters['render_analysis_tags'] = flt.render_analysis_tags
        self._app.jinja_env.filters['render_tags'] = flt.render_tags
        self._app.jinja_env.filters['replace_comparison_uid_with_hid'] = self._filter_replace_comparison_uid_with_hid
        self._app.jinja_env.filters['replace_uid_with_file_name'] = self._filter_replace_uid_with_file_name
        self._app.jinja_env.filters['replace_uid_with_hid'] = self._filter_replace_uid_with_hid
        self._app.jinja_env.filters['replace_uid_with_hid_link'] = self._filter_replace_uid_with_hid_link
        self._app.jinja_env.filters['replace_underscore'] = flt.replace_underscore_filter
        self._app.jinja_env.filters['sort_chart_list_by_name'] = flt.sort_chart_list_by_name
        self._app.jinja_env.filters['sort_chart_list_by_value'] = flt.sort_chart_list_by_value
        self._app.jinja_env.filters['sort_comments'] = flt.sort_comments
        self._app.jinja_env.filters['sort_privileges'] = lambda privileges: sorted(privileges, key=lambda role: len(privileges[role]), reverse=True)
        self._app.jinja_env.filters['sort_roles'] = flt.sort_roles_by_number_of_privileges
        self._app.jinja_env.filters['sort_users'] = flt.sort_users_by_name
        self._app.jinja_env.filters['text_highlighter'] = flt.text_highlighter
        self._app.jinja_env.filters['uids_to_link'] = flt.uids_to_link
        self._app.jinja_env.filters['user_has_role'] = flt.user_has_role
        self._app.jinja_env.filters['vulnerability_class'] = flt.vulnerability_class


class MiscellaneousRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/', 'home', self._app_home)
        self._app.add_url_rule('/about', 'about', self._app_about)
        self._app.add_url_rule('/comment/<uid>', 'comment/<uid>', self._app_add_comment, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/delete_comment/<uid>/<timestamp>', '/admin/delete_comment/<uid>/<timestamp>', self._app_delete_comment)
        self._app.add_url_rule('/admin/delete/<uid>', '/admin/delete/<uid>', self._app_delete_firmware)

    @login_required
    @roles_accepted(*PRIVILEGES['status'])
    def _app_home(self):
        stats = StatisticUpdater(config=self._config)
        with ConnectTo(FrontEndDbInterface, config=self._config) as sc:
            latest_firmware_submissions = sc.get_last_added_firmwares(int(self._config['database'].get('number_of_latest_firmwares_to_display', '10')))
            latest_comments = sc.get_latest_comments(int(self._config['database'].get('number_of_latest_firmwares_to_display', '10')))
        with ConnectTo(CompareDbInterface, config=self._config) as sc:
            latest_comparison_results = sc.page_compare_results(limit=10)
        general_stats = stats.get_general_stats()
        stats.shutdown()
        return render_template('home.html', general_stats=general_stats, latest_firmware_submissions=latest_firmware_submissions,
                               latest_comments=latest_comments, latest_comparison_results=latest_comparison_results)

    @staticmethod
    def _app_about():
        return render_template('about.html')

    @roles_accepted(*PRIVILEGES['comment'])
    def _app_add_comment(self, uid):
        error = False
        if request.method == 'POST':
            comment = request.form['comment']
            author = request.form['author']
            with ConnectTo(FrontendEditingDbInterface, config=self._config) as sc:
                sc.add_comment_to_object(uid, comment, author, round(time()))
            return redirect(url_for('analysis/<uid>', uid=uid))
        with ConnectTo(FrontEndDbInterface, config=self._config) as sc:
            if not sc.existence_quick_check(uid):
                error = True
        return render_template('add_comment.html', uid=uid, error=error)

    @roles_accepted(*PRIVILEGES['delete'])
    def _app_delete_comment(self, uid, timestamp):
        with ConnectTo(FrontendEditingDbInterface, config=self._config) as sc:
            sc.delete_comment(uid, timestamp)
        return redirect(url_for('analysis/<uid>', uid=uid))

    @roles_accepted(*PRIVILEGES['delete'])
    def _app_delete_firmware(self, uid):
        with ConnectTo(FrontEndDbInterface, config=self._config) as sc:
            is_firmware = sc.is_firmware(uid)
        if not is_firmware:
            return render_template('error.html', message='Firmware not found in database: {}'.format(uid))
        with ConnectTo(AdminDbInterface, config=self._config) as sc:
            deleted_virtual_file_path_entries, deleted_files = sc.delete_firmware(uid)
        return render_template('delete_firmware.html', deleted_vps=deleted_virtual_file_path_entries, deleted_files=deleted_files, uid=uid)


class PluginRoutes(ComponentBase):
    def _init_component(self):
        plugin_list = self._find_plugins()
        self._register_all_plugin_endpoints(plugin_list)

    def _register_all_plugin_endpoints(self, plugins_by_category):
        for plugin_type, plugin_list in plugins_by_category:
            for plugin in plugin_list:
                if self._module_has_routes(plugin, plugin_type):
                    self._import_module_routes(plugin, plugin_type)

    def _find_plugins(self):
        plugin_list = []
        for plugin_category in PLUGIN_CATEGORIES:
            plugin_list.append((plugin_category, self._get_modules_in_path('{}/{}'.format(PLUGIN_DIR, plugin_category))))
        return plugin_list

    def _module_has_routes(self, plugin, plugin_type):
        plugin_components = self._get_modules_in_path('{}/{}/{}'.format(PLUGIN_DIR, plugin_type, plugin))
        return ROUTES_MODULE_NAME in plugin_components

    def _import_module_routes(self, plugin, plugin_type):
        module = importlib.import_module('plugins.{0}.{1}.{2}.{2}'.format(plugin_type, plugin, ROUTES_MODULE_NAME))
        if hasattr(module, 'PluginRoutes'):
            module.PluginRoutes(self._app, self._config)
        for rest_class in [
            element for element in [getattr(module, attribute) for attribute in dir(module)]
            if inspect.isclass(element) and issubclass(element, Resource) and not element == Resource
        ]:
            for endpoint, methods in rest_class.ENDPOINTS:
                self._api.add_resource(rest_class, endpoint, methods=methods, resource_class_kwargs={'config': self._config})

    @staticmethod
    def _get_modules_in_path(path):
        return [module_name for _, module_name, _ in pkgutil.iter_modules([path])]

class StatisticRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule("/statistic", "statistic", self._show_statistic, methods=["GET"])
        self._app.add_url_rule("/system_health", "system_health", self._show_system_health, methods=["GET"])

    @roles_accepted(*PRIVILEGES['status'])
    def _show_statistic(self):
        filter_query = apply_filters_to_query(request, "{}")
        if filter_query == {}:
            stats = self._get_stats_from_db()
        else:
            stats = self._get_live_stats(filter_query)
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()
        return render_template("show_statistic.html", stats=stats, device_classes=device_classes,
                               vendors=vendors, current_class=str(request.args.get("device_class")),
                               current_vendor=str(request.args.get("vendor")))

    @roles_accepted(*PRIVILEGES['status'])
    def _show_system_health(self):
        components = ["frontend", "database", "backend"]
        status = []
        with ConnectTo(StatisticDbViewer, self._config) as stats_db:
            for component in components:
                status.append(stats_db.get_statistic(component))

        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            plugin_dict = sc.get_available_analysis_plugins()

        return render_template("system_health.html", status=status, analysis_plugin_info=plugin_dict)

    def _get_stats_from_db(self):
        with ConnectTo(StatisticDbViewer, self._config) as stats_db:
            stats_dict = {
                "general_stats": stats_db.get_statistic("general"),
                "firmware_meta_stats": stats_db.get_statistic("firmware_meta"),
                "file_type_stats": stats_db.get_statistic("file_type"),
                "malware_stats": stats_db.get_statistic("malware"),
                "crypto_material_stats": stats_db.get_statistic("crypto_material"),
                "unpacker_stats": stats_db.get_statistic("unpacking"),
                "ip_and_uri_stats": stats_db.get_statistic("ips_and_uris"),
                "architecture_stats": stats_db.get_statistic("architecture"),
                "release_date_stats": stats_db.get_statistic("release_date"),
                "exploit_mitigations_stats": stats_db.get_statistic("exploit_mitigations"),
                "known_vulnerabilities_stats": stats_db.get_statistic("known_vulnerabilities"),
                "software_stats": stats_db.get_statistic("software_components"),
            }
        return stats_dict

    def _get_live_stats(self, filter_query):
        with ConnectTo(StatisticUpdater, self._config) as stats_updater:
            stats_updater.set_match(filter_query)
            stats_dict = {
                "firmware_meta_stats": stats_updater.get_firmware_meta_stats(),
                "file_type_stats": stats_updater.get_file_type_stats(),
                "malware_stats": stats_updater.get_malware_stats(),
                "crypto_material_stats": stats_updater.get_crypto_material_stats(),
                "unpacker_stats": stats_updater.get_unpacking_stats(),
                "ip_and_uri_stats": stats_updater.get_ip_stats(),
                "architecture_stats": stats_updater.get_architecture_stats(),
                "release_date_stats": stats_updater.get_time_stats(),
                "general_stats": stats_updater.get_general_stats(),
                "exploit_mitigations_stats": stats_updater.get_exploit_mitigations_stats(),
                "known_vulnerabilities_stats": stats_updater.get_known_vulnerabilities_stats(),
                "software_stats": stats_updater.get_software_components_stats(),
            }
        return stats_dict

class UserManagementRoutes(ComponentBase):

    def __init__(self, app, config, api=None, user_db=None, user_db_interface=None):
        super().__init__(app, config, api=api)
        self._user_db = user_db
        self._user_db_interface = user_db_interface

    def _init_component(self):
        self._app.add_url_rule('/admin/manage_users', 'admin/manage_users', self._app_manage_users, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/user/<user_id>', 'admin/user/<user_id>', self._app_edit_user, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/edit_user', 'admin/edit_user', self._ajax_edit_user, methods=['POST'])
        self._app.add_url_rule('/admin/delete_user/<user_name>', 'admin/delete_user/<user_name>', self._app_delete_user)
        self._app.add_url_rule('/user_profile', 'user_profile', self._app_show_profile, methods=['GET', 'POST'])

    @contextmanager
    def user_db_session(self, error_message=None):
        session = self._user_db.session
        try:
            yield session
            session.commit()
        except (SQLAlchemyError, TypeError) as exception:
            logging.error('error while accessing user db: {}'.format(exception))
            session.rollback()
            if error_message:
                flash(error_message)

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _app_manage_users(self):
        if request.method == 'POST':
            self._add_user()
        user_list = self._user_db_interface.list_users()
        return render_template(
            'user_management/manage_users.html',
            users=user_list
        )

    def _add_user(self):
        name = request.form['username']
        password = request.form['password1']
        password_retype = request.form['password2']
        if self._user_db_interface.user_exists(name):
            flash('Error: user is already in the database', 'danger')
        elif password != password_retype:
            flash('Error: passwords do not match', 'danger')
        else:
            with self.user_db_session('Error while creating user'):
                self._user_db_interface.create_user(email=name, password=password)
                flash('Successfully created user', 'success')
                logging.info('Created user: {}'.format(name))

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _app_edit_user(self, user_id):
        user = self._user_db_interface.find_user(id=user_id)
        if not user:
            flash('Error: user with ID {} not found'.format(user_id), 'danger')
            return redirect(url_for('admin/manage_users'))
        if request.method == 'POST':
            self._change_user_password(user_id)
        available_roles = sorted(ROLES)
        role_indexes = [available_roles.index(r.name) for r in user.roles if r.name in ROLES]
        return render_template(
            'user_management/edit_user.html',
            available_roles=available_roles,
            user=user,
            role_indexes=role_indexes,
            privileges=PRIVILEGES
        )

    def _change_user_password(self, user_id):
        new_password = request.form['admin_change_password']
        retype_password = request.form['admin_confirm_password']
        if not new_password == retype_password:
            flash('Error: passwords do not match')
        elif not password_is_legal(new_password):
            flash('Error: password is not legal. Please choose another password.')
        else:
            user = self._user_db_interface.find_user(id=user_id)
            with self.user_db_session('Error: could not change password'):
                self._user_db_interface.change_password(user.email, new_password)
                flash('password change successful', 'success')

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _ajax_edit_user(self):
        element_name = request.values['name']
        if element_name == 'roles':
            return self._edit_roles()
        return 'Not found', 400

    def _edit_roles(self):
        user_name = request.form['pk']
        selected_role_indexes = sorted(request.form.getlist('value[]'))

        try:
            user = self._user_db_interface.find_user(email=user_name)
        except SQLAlchemyError:
            return 'Not found', 400

        added_roles, removed_roles = self._determine_role_changes(user.roles, selected_role_indexes)

        with self.user_db_session('Error: while changing roles'):
            for role in added_roles:
                if not self._user_db_interface.role_exists(role):
                    self._user_db_interface.create_role(name=role)
                    logging.info('Creating user role "{}"'.format(role))
                self._user_db_interface.add_role_to_user(user=user, role=role)

            for role in removed_roles:
                self._user_db_interface.remove_role_from_user(user=user, role=role)

        logging.info('Changed roles of user {}: added roles {}, removed roles {}'.format(user_name, added_roles, removed_roles))
        return 'OK', 200

    @staticmethod
    def _determine_role_changes(user_roles, selected_role_indexes):
        available_roles = sorted(ROLES)
        selected_roles = [available_roles[int(i)] for i in selected_role_indexes]
        current_roles = [r.name for r in user_roles if r.name in ROLES]

        added_roles = [r for r in selected_roles if r not in current_roles]
        removed_roles = [r for r in current_roles if r not in selected_roles]
        return added_roles, removed_roles

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _app_delete_user(self, user_name):
        with self.user_db_session('Error: could not delete user'):
            user = self._user_db_interface.find_user(email=user_name)
            self._user_db_interface.delete_user(user=user)
            flash('Successfully deleted user "{}"'.format(user_name), 'success')
        return redirect(url_for('admin/manage_users'))

    @roles_accepted(*PRIVILEGES['view_profile'])
    def _app_show_profile(self):
        if request.method == 'POST':
            self._change_own_password()
        return render_template('user_management/user_profile.html', user=current_user)

    def _change_own_password(self):
        new_password = request.form['new_password']
        new_password_confirm = request.form['new_password_confirm']
        old_password = request.form['old_password']
        if new_password != new_password_confirm:
            flash('Error: new password did not match', 'warning')
        elif not self._user_db_interface.password_is_correct(current_user.email, old_password):
            flash('Error: wrong password', 'warning')
        elif not password_is_legal(new_password):
            flash('Error: password is not legal. Please choose another password.')
        else:
            with self.user_db_session('Error: could not change password'):
                self._user_db_interface.change_password(current_user.email, new_password)
                flash('password change successful', 'success')
