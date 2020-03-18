import logging
import pickle
from multiprocessing import Process, Value
from time import sleep

from common_helper_mongo.gridfs import overwrite_file

from helperFunctions.database import ConnectTo
from helperFunctions.process import no_operation
from helperFunctions.yara_binary_search import YaraBinarySearchScanner
from intercom.common_mongo_binding import InterComListener, InterComListenerAndResponder, InterComMongoInterface
from storage.binary_service import BinaryService
from storage.db_interface_common import MongoInterfaceCommon
from storage.fs_organizer import FS_Organizer


class InterComBackEndBinding:
    '''
    Internal Communication Backend Binding
    '''

    def __init__(self, config=None, analysis_service=None, compare_service=None, unpacking_service=None, testing=False):
        self.config = config
        self.analysis_service = analysis_service
        self.compare_service = compare_service
        self.unpacking_service = unpacking_service
        self.poll_delay = self.config['ExpertSettings'].getfloat('intercom_poll_delay')

        self.stop_condition = Value('i', 0)
        self.process_list = []
        if not testing:
            self.startup()
        logging.info('InterCom started')

    def startup(self):
        InterComBackEndAnalysisPlugInsPublisher(config=self.config, analysis_service=self.analysis_service)
        self.start_analysis_listener()
        self.start_re_analyze_listener()
        self.start_compare_listener()
        self.start_raw_download_listener()
        self.start_tar_repack_listener()
        self.start_binary_search_listener()
        self.start_update_listener()
        self.start_delete_file_listener()
        self.start_single_analysis_listener()

    def shutdown(self):
        self.stop_condition.value = 1
        for item in self.process_list:
            item.join()
        logging.info('InterCom down')

    def start_analysis_listener(self):
        self._start_listener(InterComBackEndAnalysisTask, self.unpacking_service.add_task)

    def start_re_analyze_listener(self):
        self._start_listener(InterComBackEndReAnalyzeTask, self.unpacking_service.add_task)

    def start_update_listener(self):
        self._start_listener(InterComBackEndUpdateTask, self.analysis_service.update_analysis_of_object_and_childs)

    def start_single_analysis_listener(self):
        self._start_listener(InterComBackEndSingleFileTask, self.analysis_service.update_analysis_of_single_object)

    def start_compare_listener(self):
        self._start_listener(InterComBackEndCompareTask, self.compare_service.add_task)

    def start_raw_download_listener(self):
        self._start_listener(InterComBackEndRawDownloadTask, no_operation)

    def start_tar_repack_listener(self):
        self._start_listener(InterComBackEndTarRepackTask, no_operation)

    def start_binary_search_listener(self):
        self._start_listener(InterComBackEndBinarySearchTask, no_operation)

    def start_delete_file_listener(self):
        self._start_listener(InterComBackEndDeleteFile, no_operation)

    def _start_listener(self, communication_backend, do_after_function):
        process = Process(target=self._backend_worker, args=(communication_backend, do_after_function))
        process.start()
        self.process_list.append(process)

    def _backend_worker(self, communication_backend, do_after_function):
        interface = communication_backend(config=self.config)
        logging.debug('{} listener started'.format(type(interface).__name__))
        while self.stop_condition.value == 0:
            task = interface.get_next_task()
            if task is None:
                sleep(self.poll_delay)
            else:
                do_after_function(task)
        interface.shutdown()
        logging.debug('{} listener stopped'.format(type(interface).__name__))


class InterComBackEndAnalysisPlugInsPublisher(InterComMongoInterface):

    def __init__(self, config=None, analysis_service=None):
        super().__init__(config=config)
        self.publish_available_analysis_plugins(analysis_service)
        self.client.close()

    def publish_available_analysis_plugins(self, analysis_service):
        available_plugin_dictionary = analysis_service.get_plugin_dict()
        overwrite_file(self.connections['analysis_plugins']['fs'], 'plugin_dictonary', pickle.dumps(available_plugin_dictionary))


class InterComBackEndAnalysisTask(InterComListener):

    CONNECTION_TYPE = 'analysis_task'

    def additional_setup(self, config=None):
        self.fs_organizer = FS_Organizer(config=config)

    def post_processing(self, task, task_id):
        self.fs_organizer.store_file(task)
        return task


class InterComBackEndReAnalyzeTask(InterComListener):

    CONNECTION_TYPE = 're_analyze_task'

    def additional_setup(self, config=None):
        self.fs_organizer = FS_Organizer(config=config)

    def post_processing(self, task, task_id):
        file_path = self.fs_organizer.generate_path(task)
        task.set_file_path(file_path)
        return task


class InterComBackEndUpdateTask(InterComBackEndReAnalyzeTask):

    CONNECTION_TYPE = 'update_task'


class InterComBackEndSingleFileTask(InterComBackEndReAnalyzeTask):

    CONNECTION_TYPE = 'single_file_task'


class InterComBackEndCompareTask(InterComListener):

    CONNECTION_TYPE = 'compare_task'


class InterComBackEndRawDownloadTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'raw_download_task'
    OUTGOING_CONNECTION_TYPE = 'raw_download_task_resp'

    def get_response(self, task):
        binary_service = BinaryService(config=self.config)
        result = binary_service.get_binary_and_file_name(task)
        return result


class InterComBackEndTarRepackTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'tar_repack_task'
    OUTGOING_CONNECTION_TYPE = 'tar_repack_task_resp'

    def get_response(self, task):
        binary_service = BinaryService(config=self.config)
        result = binary_service.get_repacked_binary_and_file_name(task)
        return result


class InterComBackEndBinarySearchTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'binary_search_task'
    OUTGOING_CONNECTION_TYPE = 'binary_search_task_resp'

    def get_response(self, task):
        yara_binary_searcher = YaraBinarySearchScanner(config=self.config)
        uid_list = yara_binary_searcher.get_binary_search_result(task)
        return uid_list, task


class InterComBackEndDeleteFile(InterComListener):

    CONNECTION_TYPE = 'file_delete_task'

    def additional_setup(self, config=None):
        self.fs_organizer = FS_Organizer(config=config)

    def post_processing(self, task, task_id):
        if self._entry_was_removed_from_db(task['_id']):
            logging.info('remove file: {}'.format(task['_id']))
            self.fs_organizer.delete_file(task['_id'])

    def _entry_was_removed_from_db(self, uid):
        with ConnectTo(MongoInterfaceCommon, self.config) as db:
            if db.existence_quick_check(uid):
                logging.debug('file not removed, because database entry exists: {}'.format(uid))
                return False
            if db.check_unpacking_lock(uid):
                logging.debug('file not removed, because it is processed by unpacker: {}'.format(uid))
                return False
        return True
import logging
import pickle
from time import time

import gridfs

from helperFunctions.hash import get_sha256
from storage.mongo_interface import MongoInterface


def generate_task_id(input_data):
    serialized_data = pickle.dumps(input_data)
    task_id = '{}_{}'.format(get_sha256(serialized_data), time())
    return task_id


class InterComMongoInterface(MongoInterface):
    '''
    Common parts of the InterCom Mongo interface
    '''

    INTERCOM_CONNECTION_TYPES = [
        'test',
        'analysis_task',
        'analysis_plugins',
        're_analyze_task',
        'update_task',
        'compare_task',
        'file_delete_task',
        'raw_download_task',
        'raw_download_task_resp',
        'tar_repack_task',
        'tar_repack_task_resp',
        'binary_search_task',
        'binary_search_task_resp',
        'single_file_task'
    ]

    def _setup_database_mapping(self):
        self.connections = {}
        for item in self.INTERCOM_CONNECTION_TYPES:
            self.connections[item] = {'name': '{}_{}'.format(self.config['data_storage']['intercom_database_prefix'], item)}
            self.connections[item]['collection'] = self.client[self.connections[item]['name']]
            self.connections[item]['fs'] = gridfs.GridFS(self.connections[item]['collection'])


class InterComListener(InterComMongoInterface):
    '''
    InterCom Listener Base Class
    '''

    CONNECTION_TYPE = 'test'  # unique for each listener

    def __init__(self, config=None):
        super().__init__(config=config)
        self.additional_setup(config=config)

    def get_next_task(self):
        try:
            task_obj = self.connections[self.CONNECTION_TYPE]['fs'].find_one()
        except Exception as exc:
            logging.error('Could not get next task: {} {}'.format(type(exc), str(exc)))
            return None
        if task_obj is not None:
            task = pickle.loads(task_obj.read())
            task_id = task_obj.filename
            self.connections[self.CONNECTION_TYPE]['fs'].delete(task_obj._id)
            task = self.post_processing(task, task_id)
            logging.debug('{}: New task received: {}'.format(self.CONNECTION_TYPE, task))
            return task
        return None

    def additional_setup(self, config=None):
        '''
        optional additional setup
        '''
        pass  # pylint: disable=unnecessary-pass

    def post_processing(self, task, task_id):  # pylint: disable=no-self-use,unused-argument
        '''
        optional post processing of a task
        '''
        return task


class InterComListenerAndResponder(InterComListener):
    '''
    CONNECTION_TYPE and OUTGOING_CONNECTION_TYPE must be implmented by the sub_class
    '''

    CONNECTION_TYPE = 'test'
    OUTGOING_CONNECTION_TYPE = 'test'

    def post_processing(self, task, task_id):
        logging.debug('request received: {} -> {}'.format(self.CONNECTION_TYPE, task_id))
        response = self.get_response(task)
        self.connections[self.OUTGOING_CONNECTION_TYPE]['fs'].put(pickle.dumps(response), filename='{}'.format(task_id))
        logging.debug('response send: {} -> {}'.format(self.OUTGOING_CONNECTION_TYPE, task_id))
        return task

    def get_response(self, task):  # pylint: disable=no-self-use
        '''
        this function must be implemented by the sub_class
        '''
        return task
import logging
import pickle
from time import sleep, time

from intercom.common_mongo_binding import InterComMongoInterface, generate_task_id


class InterComFrontEndBinding(InterComMongoInterface):
    '''
    Internal Communication FrontEnd Binding
    '''

    def add_analysis_task(self, fw):
        self.connections['analysis_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)

    def add_re_analyze_task(self, fw, unpack=True):
        if unpack:
            self.connections['re_analyze_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)
        else:
            self.connections['update_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)

    def add_single_file_task(self, fw):
        self.connections['single_file_task']['fs'].put(pickle.dumps(fw), filename=fw.uid)

    def add_compare_task(self, compare_id, force=False):
        self.connections['compare_task']['fs'].put(pickle.dumps((compare_id, force)), filename=compare_id)

    def delete_file(self, fw):
        self.connections['file_delete_task']['fs'].put(pickle.dumps(fw))

    def get_available_analysis_plugins(self):
        plugin_file = self.connections['analysis_plugins']['fs'].find_one({'filename': 'plugin_dictonary'})
        if plugin_file is not None:
            plugin_dict = pickle.loads(plugin_file.read())
            return plugin_dict
        raise Exception("No available plug-ins found. FACT backend might be down!")

    def get_binary_and_filename(self, uid):
        return self._request_response_listener(uid, 'raw_download_task', 'raw_download_task_resp')

    def get_repacked_binary_and_file_name(self, uid):
        return self._request_response_listener(uid, 'tar_repack_task', 'tar_repack_task_resp')

    def add_binary_search_request(self, yara_rule_binary, firmware_uid=None):
        serialized_request = pickle.dumps((yara_rule_binary, firmware_uid))
        request_id = generate_task_id(yara_rule_binary)
        self.connections["binary_search_task"]['fs'].put(serialized_request, filename="{}".format(request_id))
        return request_id

    def get_binary_search_result(self, request_id):
        result = self._response_listener('binary_search_task_resp', request_id, timeout=time() + 10, delete=False)
        return result if result is not None else (None, None)

    def _request_response_listener(self, input_data, request_connection, response_connection):
        serialized_request = pickle.dumps(input_data)
        request_id = generate_task_id(input_data)
        self.connections[request_connection]['fs'].put(serialized_request, filename="{}".format(request_id))
        logging.debug('Request sent: {} -> {}'.format(request_connection, request_id))
        sleep(1)
        return self._response_listener(response_connection, request_id)

    def _response_listener(self, response_connection, request_id, timeout=None, delete=True):
        output_data = None
        if timeout is None:
            timeout = time() + int(self.config['ExpertSettings'].get('communication_timeout', "60"))
        while timeout > time():
            resp = self.connections[response_connection]['fs'].find_one({'filename': '{}'.format(request_id)})
            if resp:
                output_data = pickle.loads(resp.read())
                if delete:
                    self.connections[response_connection]['fs'].delete(resp._id)  # pylint: disable=protected-access
                logging.debug('Response received: {} -> {}'.format(response_connection, request_id))
                break
            else:
                logging.debug('No response yet: {} -> {}'.format(response_connection, request_id))
                sleep(1)
        return output_data
