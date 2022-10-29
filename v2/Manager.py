from DataTable import FlowDataTableV2, init_finished_flows_storage
from DummyTable import DummyTable

NEW_FLOW_TYPE = 'NEW_FLOW'
TCP_FLAGS_TYPE = 'TCP_FLAGS'


class Manager:
    def __init__(self):
        self.dataTable = DummyTable()
        self.operationalDataTable = FlowDataTableV2()
        self.save_counter = 0
        self.save_interval = 0
        self.active_flows_file = ''
        self.finished_flows_file = ''

    def initialize(self, config):
        init_finished_flows_storage(config['collect_interval'], config['save_interval'], config['finished_flows_file'])
        self.dataTable = self.operationalDataTable
        self.dataTable.initialize(config)
        self.save_counter = 0
        self.save_interval = config['save_interval']
        self.active_flows_file = config['active_flows_file']
        self.finished_flows_file = config['finished_flows_file']

    def on_update(self, pack):
        update_list = pack['update']
        stats = pack['stats']

        if update_list is None:
            print('Update list is None')
            self.handle_stats(stats)
            return

        for update in update_list:
            if update['type'] is None:
                continue

            if update['type'] == NEW_FLOW_TYPE:
                self.dataTable.on_add_flow(update)

            else:
                if update['type'] == TCP_FLAGS_TYPE:
                    self.dataTable.on_tcp_flags_package(update)

        self.handle_stats(stats)
        self.handle_save()

    def handle_stats(self, stats):
        if stats is None:
            return
        self.dataTable.on_update(stats)

    def handle_save(self):
        self.save_counter = self.save_counter + 1
        if self.save_counter == self.save_interval:
            self.save_counter = 0
            self.dataTable.on_save_flows(self.active_flows_file, self.finished_flows_file)