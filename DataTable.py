from typing import List

# functions for converting data


def get_dict_match(data):
    return {
        'ip_src': data['ip_src'],
        'ip_dst': data['ip_dst'],
        'port_src': data['port_src'],
        'port_dst': data['port_dst'],
        'protocol_code': data['protocol_code']
    }


class DataTableEntry:

    def __init__(self, start_interval, data):
        self.start_interval = start_interval
        self.finished = False
        self.ip_src = data['ip_src']
        self.ip_dst = data['ip_dst']
        self.port_src = data['port_src']
        self.port_dst = data['port_dst']
        self.protocol_code = data['protocol_code']
        self.total_byte_count = data['byte_count']
        self.total_packet_count = data['packet_count']

        self.byte_count_list = [int]
        self.packet_count_list = [int]

        self.byte_count_list.append(data['byte_count'])
        self.packet_count_list.append(data['packet_count'])

    def get_protocol_name(self):
        if self.protocol_code == 6:
            return 'TCP'
        elif self.protocol_code == 17:
            return 'UDP'
        return 'Not Supported'

    def compare_match_to_entry(self, match):
        if self.ip_src != match['ip_src']:
            if self.ip_src < match['ip_src']:
                return 1
            else:
                return -1

        if self.ip_dst != match['ip_dst']:
            if self.ip_dst < match['ip_dst']:
                return 1
            else:
                return -1

        if self.port_src != match['port_src']:
            if self.port_src < match['port_src']:
                return 1
            else:
                return -1

        if self.port_dst != match['port_dst']:
            if self.port_dst < match['port_dst']:
                return 1
            else:
                return -1

        return 0

    def update_counters(self, byte_count, packet_count):
        diff_byte_count = byte_count - self.total_byte_count
        diff_packet_count = packet_count - self.total_packet_count
        self.total_byte_count = byte_count
        self.total_packet_count = packet_count
        self.byte_count_list.append(diff_byte_count)
        self.packet_count_list.append(diff_packet_count)


class DataTable:

    def __init__(self):
        self.active_flows: List[DataTableEntry] = []
        self.finished_flows: List[DataTableEntry] = []
        self.interval = 0

    def fill_zeros(self):
        for flow in self.active_flows:
            print(flow)
            flow.update_counters(0, 0)
        self.interval = self.interval + 1

    def update_data(self, sorted_data):
        i = 0
        j = 0
        while i < len(sorted_data) and (j < len(self.active_flows)):
            value = self.active_flows[j].compare_match_to_entry(sorted_data[i])

            if value < 0:
                # new flow should be added
                new_entry = DataTableEntry(start_interval=self.interval, data=sorted_data[i])
                self.active_flows.insert(j, new_entry)
                i = i + 1
                j = j + 1
            elif value > 0:
                j = j + 1
            else:
                self.active_flows[j].update_counters(sorted_data[i]['byte_count'], sorted_data[i]['packet_count'])
                i = i + 1
                j = j + 1

        while i < len(sorted_data):
            new_entry = DataTableEntry(start_interval=self.interval, data=sorted_data[i])
            self.active_flows.append(new_entry)
            i = i + 1

        self.interval = self.interval + 1

    def find_active_flow(self, key):
        low = 0
        high = len(self.active_flows)
        while low <= high:
            mid = int((low + high) / 2)
            flow = self.active_flows[mid]
            value = flow.compare_match_to_entry(key)
            if value == 0:
                return mid
            if value < 0:
                high = mid - 1
            else:
                low = mid + 1
        return -1

    def finish_flow(self, finished_flow_data):
        index = self.find_active_flow(finished_flow_data)

        if index == -1:
            # flow not in table
            entry = DataTableEntry(self.interval, finished_flow_data)
            self.finished_flows.append(entry)
        else:
            flow = self.active_flows.pop(index)
            flow.update_counters(finished_flow_data['byte_count'], finished_flow_data['packet_count'])
            self.finished_flows.append(flow)

    def store_finished_flows_information(self):
        pass
