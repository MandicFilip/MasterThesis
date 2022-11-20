import os
from datetime import datetime
from operator import itemgetter
from FlowInfo import FlowInfo


def init_finished_flows_storage(collect_interval, save_interval, finished_flows_file):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    if os.path.exists(finished_flows_file):
        os.remove(finished_flows_file)
    try:
        file = open(finished_flows_file, "w+")
        file.write('Start time: ' + current_time + "\n")
        file.write('Collect Interval: ' + str(collect_interval) + '\n')
        file.write('Save Interval: ' + str(save_interval) + '\n\n')
        file.close()
    except IOError:
        print("Error opening file: " + finished_flows_file)


def find_flow(flows_list, key):
    low = 0
    high = len(flows_list) - 1
    while low <= high:
        mid = int((low + high) / 2)
        flow = flows_list[mid]
        value = flow.compare_match_to_entry(key)
        if value == 0:
            return mid
        if value < 0:
            high = mid - 1
        else:
            low = mid + 1
    return -1


def insert_into_sorted_list(flow_list, flow):
    i = 0
    while i < len(flow_list) and flow_list[i].compare_flows(flow) == 1:
        i = i + 1
    flow_list.insert(i, flow)
    return flow_list


def check_data(data):
    i = 0
    while i < len(data):
        flow = data[i]
        if 'ip_src' in flow and 'ip_dst' in flow and 'port_src' in flow and 'port_dst' in flow and 'protocol_code' in flow and 'byte_count' in flow and 'packet_count' in flow:
            i = i + 1
        else:
            print('Bad flow -> ' + str(flow))
            data.pop(i)


class FlowDataTableV2:
    def __init__(self):
        self.is_initialized = False
        self.active_flows = []
        self.finished_flows = []
        self.interval = 0
        self.dns_flows = []
        self.add_counter = 0
        self.remove_counter = 0
        self.tcp_idle_interval = 0
        self.udp_idle_interval = 0

    # public
    def initialize(self, config):
        self.tcp_idle_interval = config['tcp_idle_interval']
        self.udp_idle_interval = config['udp_idle_interval']

    def on_insert_values(self, update_flows):
        active = []

        for flow in update_list:
            if flow['type'] is None:
                continue

            if flow['type'] == NEW_FLOW_TYPE:
                self.dataTable.on_add_flow(flow)

            else:
                if flow['type'] == TCP_FLAGS_TYPE:
                    self.dataTable.on_tcp_flags_package(flow)

    # public
    def on_add_flow(self, info):
        self.add_counter = self.add_counter + 1
        new_flow = FlowInfo(self.interval, info, self.tcp_idle_interval, self.udp_idle_interval)
        if new_flow.is_dns_communication():
            self.dns_flows = insert_into_sorted_list(self.dns_flows, new_flow)
            new_flow.process_dns()
        else:
            self.active_flows = insert_into_sorted_list(self.active_flows, new_flow)
        return new_flow

    # public
    def on_tcp_flags_package(self, tcp_flow_data):
        index = self.find_active_flow(tcp_flow_data)
        exists = index != -1
        if exists:
            flow = self.active_flows[index]
            flow.add_last_tcp_package_data(self.interval, tcp_flow_data['byte_count'], tcp_flow_data['packet_count'])
        else:
            new_flow = self.on_add_flow(tcp_flow_data)
            new_flow.set_tcp_finished_flag()

    # public
    def on_update(self, data):
        check_data(data)
        data.sort(key=itemgetter('ip_src', 'ip_dst', 'port_src', 'port_dst'))
        self.update_active_flows_table(data)
        self.update_flow_status()

    def update_active_flows_table(self, sorted_data):
        i = 0
        j = 0
        while (i < len(sorted_data)) and (j < len(self.active_flows)):
            value = self.active_flows[j].compare_match_to_entry(sorted_data[i])

            if value < 0:
                # There is a flow that we are unaware of - could be that the first package in .pcap is tcp finish
                i = i + 1
            elif value > 0:
                # finished flow, no input for it
                self.active_flows[j].add_zeros()
                j = j + 1
            else:
                self.active_flows[j].update_counters(sorted_data[i]['byte_count'], sorted_data[i]['packet_count'])
                i = i + 1
                j = j + 1

        while j < len(self.active_flows):
            self.active_flows[j].add_zeros()
            j = j + 1

        self.interval = self.interval + 1

    def list_to_string(self):
        i = 0
        s = ''
        while i < len(self.active_flows):
            s = s + self.active_flows[i].to_string_match() + '\n'
            i = i + 1

        return s

    def update_flow_status(self):
        i = 0

        while i < len(self.active_flows):
            flow = self.active_flows[i]
            flow.update_status()

            if flow.is_active():
                if not flow.has_pair():
                    pair = self.find_pair_for_flow(flow)
                    if pair is not None:
                        if not pair.has_pair():
                            flow.set_pair(pair)
                            pair.set_pair(flow)
                            flow.align_tcp_interval_start()
                i = i + 1
            else:
                self.finished_flows.append(flow)
                self.active_flows.pop(i)

        i = 0
        while i < len(self.finished_flows):
            flow = self.finished_flows[i]
            pair = flow.get_pair()
            if pair is not None:
                if pair.is_waiting() or pair.is_finished():
                    flow.set_finished()
                    pair.set_finished()
            i = i + 1

        while len(self.dns_flows) > 0:
            dns_flow = self.dns_flows.pop()
            self.finished_flows.append(dns_flow)

    def clear_finished_flows(self):
        # remove all flows marked as finished
        i = 0
        while i < len(self.finished_flows):
            if self.finished_flows[i].is_finished():
                self.finished_flows.pop(i)
            else:
                i = i + 1

    # public
    def on_save_flows(self, active_flows_file, finished_flows_file):
        self.save_active_flows(active_flows_file)
        self.save_finished_flows(finished_flows_file)
        self.clear_finished_flows()

    # public
    def calc_stats(self):
        for flow in self.finished_flows:
            if flow.is_finished():
                flow.calc_stats()

    def find_active_flow(self, key):
        return find_flow(self.active_flows, key)

    def find_finish_flow(self, key):
        return find_flow(self.finished_flows, key)

    def find_dns_flow(self, key):
        return find_flow(self.dns_flows, key)

    def find_pair_for_flow(self, flow):
        key = flow.create_opposite_entry()
        index = self.find_active_flow(key)
        if index != -1:
            return self.active_flows[index]
        return None

    def save_active_flows(self, file):
        if os.path.exists(file):
            os.remove(file)
        try:
            file = open(file, "w+")
            for flow in self.active_flows:
                flow_string = flow.get_file_output_string(self.interval, False, True)
                file.write(flow_string)
                file.write("\n")

            for flow in self.finished_flows:
                if not flow.is_finished():
                    flow_string = flow.get_file_output_string(self.interval, False, True)
                    file.write(flow_string)
                    file.write("\n")
            file.close()
        except IOError:
            print("Error opening file: " + file)

    def save_finished_flows(self, file):
        if not os.path.exists(file):
            print("File does not exist!")
            return False
        try:
            file = open(file, "a")
            for flow in self.finished_flows:
                if flow.is_finished():
                    flow_string = flow.get_file_output_string(self.interval, True, False)
                    file.write(flow_string)
                    file.write("\n")

            file.close()
        except IOError:
            print("Error saving finished flows")

    def get_interval(self):
        return self.interval
