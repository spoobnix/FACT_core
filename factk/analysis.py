from .plugins import * # analysismeta

class AnalysisBasePlugin(BasePlugin):  # pylint: disable=too-many-instance-attributes
    '''
    This is the base plugin. All plugins should be subclass of this.
    recursive flag: If True (default) recursively analyze included files
    '''
    VERSION = 'not set'
    SYSTEM_VERSION = None

    timeout = None

    def __init__(self, plugin_administrator, config=None, recursive=True, no_multithread=False, timeout=300, offline_testing=False, plugin_path=None):  # pylint: disable=too-many-arguments
        super().__init__(plugin_administrator, config=config, plugin_path=plugin_path)
        self.check_config(no_multithread)
        self.recursive = recursive
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.stop_condition = Value('i', 0)
        self.workers = []
        if self.timeout is None:
            self.timeout = timeout
        self.register_plugin()
        if not offline_testing:
            self.start_worker()

    def add_job(self, fw_object: FileObject):
        if self._dependencies_are_unfulfilled(fw_object):
            logging.error('{}: dependencies of plugin {} not fulfilled'.format(fw_object.uid, self.NAME))
        elif self._analysis_depth_not_reached_yet(fw_object):
            self.in_queue.put(fw_object)
            return
        self.out_queue.put(fw_object)

    def _dependencies_are_unfulfilled(self, fw_object: FileObject):
        # FIXME plugins can be in processed_analysis and could still be skipped, etc. -> need a way to verify that
        # FIXME the analysis ran successfully
        return any(dep not in fw_object.processed_analysis for dep in self.DEPENDENCIES)

    def _analysis_depth_not_reached_yet(self, fo):
        return self.recursive or fo.depth == 0

    def process_object(self, file_object):  # pylint: disable=no-self-use
        '''
        This function must be implemented by the plugin
        '''
        return file_object

    def analyze_file(self, file_object):
        fo = self.process_object(file_object)
        fo = self._add_plugin_version_and_timestamp_to_analysis_result(fo)
        return fo

    def _add_plugin_version_and_timestamp_to_analysis_result(self, fo):
        fo.processed_analysis[self.NAME].update(self.init_dict())
        return fo

    def shutdown(self):
        '''
        This function can be called to shutdown all working threads
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        for process in self.workers:
            process.join()
        self.in_queue.close()
        self.out_queue.close()

# ---- internal functions ----

    def add_analysis_tag(self, file_object, tag_name, value, color=TagColor.LIGHT_BLUE, propagate=False):
        new_tag = {
            tag_name: {
                'value': value,
                'color': color,
                'propagate': propagate,
            },
            'root_uid': file_object.get_root_uid()
        }
        if 'tags' not in file_object.processed_analysis[self.NAME]:
            file_object.processed_analysis[self.NAME]['tags'] = new_tag
        else:
            file_object.processed_analysis[self.NAME]['tags'].update(new_tag)

    def init_dict(self):
        result_update = {'analysis_date': time(), 'plugin_version': self.VERSION}
        if self.SYSTEM_VERSION:
            result_update.update({'system_version': self.SYSTEM_VERSION})
        return result_update

    def check_config(self, no_multithread):
        if self.NAME not in self.config:
            self.config.add_section(self.NAME)
        if 'threads' not in self.config[self.NAME] or no_multithread:
            self.config.set(self.NAME, 'threads', '1')

    def start_worker(self):
        for process_index in range(int(self.config[self.NAME]['threads'])):
            self.workers.append(start_single_worker(process_index, 'Analysis', self.worker))
        logging.debug('{}: {} worker threads started'.format(self.NAME, len(self.workers)))

    def process_next_object(self, task, result):
        task.processed_analysis.update({self.NAME: {}})
        finished_task = self.analyze_file(task)
        result.append(finished_task)

    @staticmethod
    def timeout_happened(process):
        return process.is_alive()

    def worker_processing_with_timeout(self, worker_id, next_task):
        manager = Manager()
        result = manager.list()
        process = ExceptionSafeProcess(target=self.process_next_object, args=(next_task, result))
        process.start()
        process.join(timeout=self.timeout)
        if self.timeout_happened(process):
            terminate_process_and_childs(process)
            self.out_queue.put(next_task)
            logging.warning('Worker {}: Timeout {} analysis on {}'.format(worker_id, self.NAME, next_task.uid))
        elif process.exception:
            terminate_process_and_childs(process)
            raise process.exception[0]
        else:
            self.out_queue.put(result.pop())
            logging.debug('Worker {}: Finished {} analysis on {}'.format(worker_id, self.NAME, next_task.uid))

    def worker(self, worker_id):
        while self.stop_condition.value == 0:
            try:
                next_task = self.in_queue.get(timeout=float(self.config['ExpertSettings']['block_delay']))
                logging.debug('Worker {}: Begin {} analysis on {}'.format(worker_id, self.NAME, next_task.uid))
            except Empty:
                pass
            else:
                next_task.processed_analysis.update({self.NAME: {}})
                self.worker_processing_with_timeout(worker_id, next_task)

        logging.debug('worker {} stopped'.format(worker_id))

    def check_exceptions(self):
        return check_worker_exceptions(self.workers, 'Analysis', self.config, self.worker)
import json
import logging
import re
import subprocess
from pathlib import Path

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.fileSystem import get_src_dir


class YaraBasePlugin(AnalysisBasePlugin):
    '''
    This should be the base for all YARA based analysis plugins
    '''
    NAME = 'Yara_Base_Plugin'
    DESCRIPTION = 'this is a Yara plugin'
    VERSION = '0.0'

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=None):
        '''
        recursive flag: If True recursively analyze included files
        propagate flag: If True add analysis result of child to parent object
        '''
        self.config = config
        self.signature_path = self._get_signature_file(plugin_path) if plugin_path else None
        self.SYSTEM_VERSION = self.get_yara_system_version()
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)

    def get_yara_system_version(self):
        with subprocess.Popen(['yara', '--version'], stdout=subprocess.PIPE) as process:
            yara_version = process.stdout.readline().decode().strip()

        access_time = int(Path(self.signature_path).stat().st_mtime)
        return '{}_{}'.format(yara_version, access_time)

    def process_object(self, file_object):
        if self.signature_path is not None:
            with subprocess.Popen('yara --print-meta --print-strings {} {}'.format(self.signature_path, file_object.file_path), shell=True, stdout=subprocess.PIPE) as process:
                output = process.stdout.read().decode()
            try:
                result = self._parse_yara_output(output)
                file_object.processed_analysis[self.NAME] = result
                file_object.processed_analysis[self.NAME]['summary'] = list(result.keys())
            except (ValueError, TypeError):
                file_object.processed_analysis[self.NAME] = {'ERROR': 'Processing corrupted. Likely bad call to yara.'}
        else:
            file_object.processed_analysis[self.NAME] = {'ERROR': 'Signature path not set'}
        return file_object

    @staticmethod
    def _get_signature_file_name(plugin_path):
        return plugin_path.split('/')[-3] + '.yc'

    def _get_signature_file(self, plugin_path):
        sig_file_name = self._get_signature_file_name(plugin_path)
        return str(Path(get_src_dir()) / 'analysis/signatures' / sig_file_name)

    @staticmethod
    def _parse_yara_output(output):
        resulting_matches = dict()

        match_blocks, rules = _split_output_in_rules_and_matches(output)

        matches_regex = re.compile(r'((0x[a-f0-9]*):(\S+):\s(.+))+')
        for index, rule in enumerate(rules):
            for match in matches_regex.findall(match_blocks[index]):
                _append_match_to_result(match, resulting_matches, rule)

        return resulting_matches


def _split_output_in_rules_and_matches(output):
    split_regex = re.compile(r'\n*.*\[.*\]\s/.+\n*')
    match_blocks = split_regex.split(output)
    while '' in match_blocks:
        match_blocks.remove('')

    rule_regex = re.compile(r'(\w*)\s\[(.*)\]\s([.]{0,2}/)(.+)')
    rules = rule_regex.findall(output)

    if not len(match_blocks) == len(rules):
        raise ValueError()
    return match_blocks, rules


def _append_match_to_result(match, resulting_matches, rule):
    rule_name, meta_string, _, _ = rule
    _, offset, matched_tag, matched_string = match

    meta_dict = _parse_meta_data(meta_string)

    this_match = resulting_matches[rule_name] if rule_name in resulting_matches else dict(rule=rule_name, matches=True, strings=list(), meta=meta_dict)

    this_match['strings'].append((int(offset, 16), matched_tag, matched_string.encode()))
    resulting_matches[rule_name] = this_match


def _parse_meta_data(meta_data_string):
    '''
    Will be of form 'item0=lowercaseboolean0,item1="value1",item2=value2,..'
    '''
    meta_data = dict()
    for item in meta_data_string.split(','):
        if '=' in item:
            key, value = item.split('=', maxsplit=1)
            value = json.loads(value) if value in ['true', 'false'] else value.strip('"')
            meta_data[key] = value
        else:
            logging.warning('Malformed meta string \'{}\''.format(meta_data_string))
    return meta_data
