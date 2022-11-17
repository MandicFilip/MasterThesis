from DataTable import FlowDataTableV2, init_finished_flows_storage
from DummyTable import DummyTable
import time

NEW_FLOW_TYPE = 'NEW_FLOW'
TCP_FLAGS_TYPE = 'TCP_FLAGS'

PERFORMANCE_FILE = 'performance.info'


class Manager:
    def __init__(self):
        self.dataTable = DummyTable()
        self.operationalDataTable = FlowDataTableV2()
        self.save_counter = 0
        self.save_interval = 0
        self.active_flows_file = ''
        self.finished_flows_file = ''
        self.performance_reports = []

    def initialize(self, config):
        init_finished_flows_storage(config['collect_interval'], config['save_interval'], config['finished_flows_file'])
        self.dataTable = self.operationalDataTable
        self.dataTable.initialize(config)
        self.save_counter = 0
        self.save_interval = config['save_interval']
        self.active_flows_file = config['active_flows_file']
        self.finished_flows_file = config['finished_flows_file']

    def on_update(self, pack):
        start_time = round(time.time() * 1000)
        update_list = pack['update']
        stats = pack['stats']

        if update_list is None:
            print('Update list is None')
            self.handle_stats(stats)
            return

        print('Update list size: ' + str(len(update_list)))
        for flow in update_list:
            if flow['type'] is None:
                continue

            if flow['type'] == NEW_FLOW_TYPE:
                self.dataTable.on_add_flow(flow)

            else:
                if flow['type'] == TCP_FLAGS_TYPE:
                    self.dataTable.on_tcp_flags_package(flow)

        update_flows_end = round(time.time() * 1000)

        self.handle_stats(stats)
        update_stats_end = round(time.time() * 1000)

        calc_time, save_time = self.handle_save()

        end = round(time.time() * 1000)
        total_time = end - start_time
        update_flows_time = update_flows_end - start_time
        update_stats_time = update_stats_end - update_flows_end

        report = f'Total time(ms): {str(total_time)}    (flows update, stats update, calc, save): ({str(update_flows_time)}, {str(update_stats_time)}, {str(calc_time)}, {str(save_time)})\n'
        print(report)
        self.performance_reports.append('Interval: ' + str(self.dataTable.get_interval()) + '   ' + report)

    def handle_stats(self, stats):
        if stats is None:
            return
        print('Stats list size: ' + str(len(stats)))
        self.dataTable.on_update(stats)

    def handle_save(self):
        self.save_counter = self.save_counter + 1
        if self.save_counter == self.save_interval:
            self.save_counter = 0
            start = round(time.time() * 1000)
            self.dataTable.calc_stats()
            mid = round(time.time() * 1000)
            self.dataTable.on_save_flows(self.active_flows_file, self.finished_flows_file)
            self.write_performance_analysis()
            end = round(time.time() * 1000)
            calc_time = mid - start
            save_time = end - mid
            return calc_time, save_time
        return 0, 0

    def write_performance_analysis(self):
        performance_file = open(PERFORMANCE_FILE, "a")

        for report in self.performance_reports:
            performance_file.write(report)

        self.performance_reports.clear()
        performance_file.close()
