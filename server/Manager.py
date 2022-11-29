from DataTable import FlowDataTable, init_finished_flows_storage
from DummyTable import DummyTable
import time

NEW_FLOW_TYPE = 'NEW_FLOW'
TCP_FLAGS_TYPE = 'TCP_FLAGS'

PERFORMANCE_FILE = 'performance.info'
CSV_FORMAT_FILE = 'performance.csv'


class Manager:
    def __init__(self):
        self.dataTable = DummyTable()
        self.operationalDataTable = FlowDataTable()
        self.save_counter = 0
        self.save_interval = 0
        self.active_flows_file = ''
        self.finished_flows_file = ''
        self.performance_data = []
        self.init_csv_file()

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

        self.dataTable.on_insert_values(update_list)
        update_flows = round(time.time() * 1000) - start_time

        update_counters, update_state = self.handle_stats(stats)

        calc_time, save_time = self.handle_save()

        total_time = round(time.time() * 1000) - start_time

        self.save_performance(pack, update_flows, update_counters, update_state, calc_time, save_time, total_time)

    def handle_stats(self, stats):
        if stats is None:
            return 0, 0

        start_time = round(time.time() * 1000)
        self.dataTable.on_update(stats)
        end_update_counters = round(time.time() * 1000)
        update_counters = end_update_counters - start_time
        self.dataTable.update_flow_status()
        update_state = round(time.time() * 1000) - end_update_counters
        return update_counters, update_state

    def handle_save(self):
        self.save_counter = self.save_counter + 1
        if self.save_counter == self.save_interval:
            self.save_counter = 0
            start = round(time.time() * 1000)
            self.dataTable.calc_stats()
            mid = round(time.time() * 1000)
            self.dataTable.on_save_flows(self.active_flows_file, self.finished_flows_file)
            end = round(time.time() * 1000)
            self.write_performance_analysis()
            calc_time = mid - start
            save_time = end - mid
            return calc_time, save_time
        return 0, 0

    def save_performance(self, pack, update_flows, update_counters, update_state, calc_time, save_time, total_time):
        performance_struct = {}
        performance_struct['interval'] = str(self.dataTable.get_interval())

        performance_struct['total_time'] = str(total_time)
        performance_struct['update_flows'] = str(update_flows)
        performance_struct['update_counters'] = str(update_counters)
        performance_struct['update_state'] = str(update_state)
        performance_struct['calc_time'] = str(calc_time)
        performance_struct['save_time'] = str(save_time)
        performance_struct['queue_time'] = str(pack['get_time'] - pack['put_time'])

        performance_struct['active'] = str(len(self.dataTable.active_flows))
        performance_struct['finished'] = str(len(self.dataTable.finished_flows))
        performance_struct['insert'] = str(len(pack['update']))
        performance_struct['stats'] = str(len(pack['stats']))
        performance_struct['queue_size'] = str(pack['queue_size'])

        print(f'Interval: {self.dataTable.get_interval()}   total_time: {total_time}   active: {str(len(self.dataTable.active_flows))}   finished: {str(len(self.dataTable.finished_flows))}' + '\n')
        self.performance_data.append(performance_struct)

    def generate_report(self, performance_struct):
        interval = performance_struct['interval']

        total_time = performance_struct['total_time']
        update_flows = performance_struct['update_flows']
        update_counters = performance_struct['update_counters']
        update_state = performance_struct['update_state']
        calc_time = performance_struct['calc_time']
        save_time = performance_struct['save_time']
        queue_time = performance_struct['queue_time']

        active = performance_struct['active']
        finished = performance_struct['finished']
        insert = performance_struct['insert']
        stats = performance_struct['stats']
        queue_size = performance_struct['queue_size']

        report = f'Interval: {interval}'
        report = report + f'   Time(ms): (Total, insert, update counters, update state, calc, save, queue): '
        report = report + f'({total_time}, {update_flows}, {update_counters}, {update_state}, {calc_time}, {save_time}, {queue_time})'
        report = report + f'     size: (active, finished, insert, update, queue):  '
        report = report + f'({active}, {finished}, {insert}, {stats}, {queue_size})\n'

        csv_line = f"{interval},{total_time},{update_flows},{update_counters},{update_state},{calc_time},{save_time},{queue_time},{active},{finished},{insert},{stats},{queue_size}\n"
        return report, csv_line

    def write_performance_analysis(self):
        performance_file = open(PERFORMANCE_FILE, "a")
        csv_file = open(CSV_FORMAT_FILE, "a")

        for perf in self.performance_data:
            report, csv_line = self.generate_report(perf)
            performance_file.write(report)
            csv_file.write(csv_line)

        self.performance_data.clear()
        performance_file.close()

    def init_csv_file(self):
        csv_file = open(CSV_FORMAT_FILE, "a")
        csv_file.write("interval, total, insert, update counters, update state, calc, save, queue time, active, finished, insert, update, queue size\n")
        csv_file.close()
