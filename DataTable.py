from typing import List


class DataTableEntry:

    def __init__(self, start_interval, match, byte_count, packet_count):
        self.start_interval = start_interval
        self.match = match
        self.total_byte_count = byte_count
        self.total_packet_count = packet_count

        self.byte_count_list = [int]
        self.packet_count_list = [int]

        self.byte_count_list.append(byte_count)
        self.packet_count_list.append(packet_count)

    def is_match(self, match):
        return self.match == match

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

    def fill_zeros(self):
        for flow in self.active_flows:
            print(flow)
            flow.update_counters(0, 0)

    def update_data(self, sorted_data):
        pass

    def store_finished_flows_information(self):
        pass
