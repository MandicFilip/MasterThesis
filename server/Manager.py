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

        report = self.generate_report(pack, start_time, update_flows_end, update_stats_end, calc_time, save_time, end)
        print(report + '\n')
        self.performance_reports.append(report)

    def handle_stats(self, stats):
        if stats is None:
            return
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

    def generate_report(self, pack, start_time, update_flows_end, update_stats_end, calc_time, save_time, end_time):
        update_list = pack['update']
        stats = pack['stats']
        total_time = end_time - start_time
        update_flows_time = update_flows_end - start_time
        update_stats_time = update_stats_end - update_flows_end
        queue_time = pack['get_time'] - pack['put_time']
        queue_size = pack['queue_size']

        report = f'Interval: {str(self.dataTable.get_interval())}'
        report = report + f'   Time(ms): (Total, insert, update, calc, save, queue): '
        report = report + f'({str(total_time)}, {str(update_flows_time)}, {str(update_stats_time)}, {str(calc_time)}, {str(save_time)}, {str(queue_time)})'
        report = report + f'     size: (active, finished, insert, update, queue):  '
        report = report + f'({str(len(self.dataTable.active_flows))}, {str(len(self.dataTable.finished_flows))}, {str(len(update_list))}, {str(len(stats))}, {str(queue_size)})\n'
        return report

    def write_performance_analysis(self):
        performance_file = open(PERFORMANCE_FILE, "a")

        for report in self.performance_reports:
            performance_file.write(report)

        self.performance_reports.clear()
        performance_file.close()
