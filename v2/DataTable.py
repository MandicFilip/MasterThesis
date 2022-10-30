import os
from datetime import datetime
import statistics
import scipy.stats
from operator import itemgetter

TCP_PROTOCOL_CODE = 6
UDP_PROTOCOL_CODE = 17
DNS_PORT = 53

MIN_LENGTH = 2

STATUS_ACTIVE = 1
STATUS_WAITING = 2
STATUS_FINISHED = 3

# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------DEBUG-----------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

marked_flows = [
    {'ip_src': '184.51.9.98', 'ip_dst': '192.168.0.25', 'port_src': 443, 'port_dst': 61185, 'protocol_code': 6},
    {'ip_src': '192.168.0.15', 'ip_dst': '239.255.255.250', 'port_src': 60151, 'port_dst': 1900, 'protocol_code': 17},
]


def check_in_marked_flows(flow):
    for marked in marked_flows:
        if flow['ip_src'] == marked['ip_src'] and flow['ip_dst'] == marked['ip_dst'] and \
                flow['port_src'] == marked['port_src'] and flow['port_dst'] == marked['port_dst']:
            return True
    return False


# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------STORAGE---------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------


def stringify_statistics(flow):
    stats = ""
    stats = stats + str(flow.data.byte_mean) + " "
    stats = stats + str(flow.data.byte_median) + " "
    stats = stats + str(flow.data.byte_mode) + " "
    stats = stats + str(flow.data.byte_standard_deviation) + " "
    stats = stats + str(flow.data.byte_fisher_skew) + " "
    stats = stats + str(flow.data.byte_fisher_kurtosis) + " "
    stats = stats + str(flow.data.byte_correlation) + "\n"

    stats = stats + str(flow.data.packet_mean) + " "
    stats = stats + str(flow.data.packet_median) + " "
    stats = stats + str(flow.data.packet_mode) + " "
    stats = stats + str(flow.data.packet_standard_deviation) + " "
    stats = stats + str(flow.data.packet_fisher_skew) + " "
    stats = stats + str(flow.data.packet_fisher_kurtosis) + " "
    stats = stats + str(flow.data.packet_correlation) + "\n"
    return stats


def format_flow_info(flow):
    flow_string = ""
    flow_string = flow_string + str(flow.match.ip_src) + " "
    flow_string = flow_string + str(flow.match.ip_dst) + " "
    flow_string = flow_string + str(flow.match.port_src) + " "
    flow_string = flow_string + str(flow.match.port_dst) + " "
    flow_string = flow_string + str(flow.match.protocol_code) + "\n"

    flow_string = flow_string + str(flow.data.byte_count_list) + "\n"
    flow_string = flow_string + str(flow.data.packet_count_list) + "\n"

    flow_string = flow_string + stringify_statistics(flow) + "\n"
    return flow_string


def init_file(file, time, collect_interval, save_interval):
    if os.path.exists(file):
        os.remove(file)
    try:
        file = open(file, "w+")
        file.write('Start time: ' + time + "\n")
        file.write('Collect Interval: ' + str(collect_interval) + '\n')
        file.write('Save Interval: ' + str(save_interval) + '\n\n')
        file.close()
    except IOError:
        print("Error opening file: " + file)


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


def save_active_flows(file, active_flows, finished_flows):
    if os.path.exists(file):
        os.remove(file)
    try:
        file = open(file, "w+")
        for flow in active_flows:
            flow_string = format_flow_info(flow)
            file.write(flow_string)
            file.write("\n")

        for flow in finished_flows:
            if not flow.is_finished():
                flow_string = format_flow_info(flow)
                file.write(flow_string)
                file.write("\n")
        file.close()
    except IOError:
        print("Error opening file: " + file)


def save_finished_flows(file, flows):
    if not os.path.exists(file):
        print("File does not exist!")
        return False
    try:
        file = open(file, "a")
        for flow in flows:
            if flow.is_finished():
                flow_string = format_flow_info(flow)
                file.write(flow_string)
                file.write("\n")

        file.close()
        return True
    except IOError:
        print("Error saving finished flows")
        return False


# ----------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------FLOW-----------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

class MatchV2:
    def __init__(self, entry):
        self.ip_src = entry['ip_src']
        self.ip_dst = entry['ip_dst']
        self.port_src = entry['port_src']
        self.port_dst = entry['port_dst']
        self.protocol_code = entry['protocol_code']

    def compare_match_to_entry(self, entry):
        if self.ip_src != entry['ip_src']:
            if self.ip_src < entry['ip_src']:
                return 1
            else:
                return -1

        if self.ip_dst != entry['ip_dst']:
            if self.ip_dst < entry['ip_dst']:
                return 1
            else:
                return -1

        if self.port_src != entry['port_src']:
            if self.port_src < entry['port_src']:
                return 1
            else:
                return -1

        if self.port_dst != entry['port_dst']:
            if self.port_dst < entry['port_dst']:
                return 1
            else:
                return -1

        return 0

    def compare_match(self, match):
        entry = {'ip_src': match.ip_src, 'ip_dst': match.ip_dst,
                 'port_src': match.port_src, 'port_dst': match.port_dst}
        return self.compare_match_to_entry(entry)

    def create_opposite_entry(self):
        return {'ip_src': self.ip_dst, 'ip_dst': self.ip_src,
                'port_src': self.port_dst, 'port_dst': self.port_src, 'protocol_code': self.protocol_code}

    def get_protocol_name(self):
        if self.protocol_code == TCP_PROTOCOL_CODE:
            return 'TCP'
        elif self.protocol_code == UDP_PROTOCOL_CODE:
            return 'UDP'
        return 'Not Supported'

    def is_dns_communication(self):
        return self.is_udp() and (self.port_src == DNS_PORT or self.port_dst == DNS_PORT)

    def get_entry(self):
        return {'ip_src': self.ip_src, 'ip_dst': self.ip_dst,
                'port_src': self.port_src, 'port_dst': self.port_dst, 'protocol_code': self.protocol_code}

    def is_tcp(self):
        return self.protocol_code == TCP_PROTOCOL_CODE

    def is_udp(self):
        return self.protocol_code == UDP_PROTOCOL_CODE

    def to_string(self):
        return '{ip_src: ' + self.ip_src + ', ip_dst: ' + self.ip_dst + ', port_src: ' + str(self.port_src) + \
               ', port_dst:' + str(self.port_dst) + '}'


class DataV2:
    # public data -> hash map with byte_count and packet_count
    def __init__(self, data):
        self.additional_bytes = data['byte_count']
        self.additional_packets = data['packet_count']
        self.tcp_flags_interval = -1

        self.previous_byte_count = 0
        self.previous_packet_count = 0
        self.byte_count_list = []
        self.packet_count_list = []

        self.byte_mean = 0
        self.packet_mean = 0

        self.byte_median = 0
        self.packet_median = 0

        self.byte_mode = 0
        self.packet_mode = 0

        self.byte_standard_deviation = 0
        self.packet_standard_deviation = 0

        self.byte_fisher_skew = 0
        self.packet_fisher_skew = 0

        self.byte_fisher_kurtosis = 0
        self.packet_fisher_kurtosis = 0

        self.byte_correlation = 0
        self.packet_correlation = 0

    def get_lists(self):
        return self.byte_count_list, self.packet_count_list

    # public - called from update
    def append_data(self, total_byte_count, total_packet_count):
        byte_count, packet_count = self.get_interval_values(total_byte_count, total_packet_count)

        byte_count = byte_count + self.additional_bytes
        packet_count = packet_count + self.additional_packets

        self.byte_count_list.append(byte_count)
        self.packet_count_list.append(packet_count)

        self.previous_byte_count = total_byte_count
        self.previous_packet_count = total_packet_count

        self.additional_bytes = 0
        self.additional_packets = 0

    def append_zeros(self):
        self.append_data(self.previous_byte_count, self.previous_packet_count)

    # public - called from tcp flags
    def add_tcp_flags_data(self, interval, byte_count, packet_count):
        self.additional_bytes = byte_count
        self.additional_packets = packet_count
        self.tcp_flags_interval = interval

    # public - called from removed
    def remove_padding(self):
        while len(self.byte_count_list) > 0 and self.byte_count_list[-1] == 0:
            del self.byte_count_list[-1:]
            del self.packet_count_list[-1:]

    def get_interval_values(self, total_byte_count, total_packet_count):
        byte_count = total_byte_count - self.previous_byte_count
        packet_count = total_packet_count - self.previous_packet_count
        return byte_count, packet_count

    def calc_self_stats(self):
        if len(self.byte_count_list) > MIN_LENGTH:
            self.calc_mean()
            self.calc_median()
            self.calc_mode()
            self.calc_standard_deviation()
            self.calc_skew()
            self.calc_kurtosis()

    def calc_mean(self):
        self.byte_mean = statistics.mean(self.byte_count_list)
        self.packet_mean = statistics.mean(self.packet_count_list)

    def calc_median(self):
        self.byte_median = statistics.median(self.byte_count_list)
        self.packet_median = statistics.median(self.packet_count_list)

    def calc_mode(self):
        self.byte_mode = scipy.stats.mode(self.byte_count_list, keepdims=True).mode[0]
        self.packet_mode = scipy.stats.mode(self.packet_count_list, keepdims=True).mode[0]

    def calc_standard_deviation(self):
        self.byte_standard_deviation = statistics.stdev(self.byte_count_list)
        self.packet_standard_deviation = statistics.stdev(self.packet_count_list)

    def calc_skew(self):
        self.byte_fisher_skew = scipy.stats.skew(self.byte_count_list)
        self.packet_fisher_skew = scipy.stats.skew(self.packet_count_list)

    def calc_kurtosis(self):
        self.byte_fisher_kurtosis = scipy.stats.kurtosis(self.byte_count_list)
        self.packet_fisher_kurtosis = scipy.stats.kurtosis(self.packet_count_list)

    def calc_correlation(self, pair_byte_list, pair_packet_list):
        if len(self.byte_count_list) > MIN_LENGTH:
            self.byte_correlation = scipy.stats.pearsonr(self.byte_count_list, pair_byte_list)
            self.packet_correlation = scipy.stats.pearsonr(self.packet_count_list, pair_packet_list)

    def reset_stats(self):
        self.byte_mean = 0
        self.packet_mean = 0

        self.byte_median = 0
        self.packet_median = 0

        self.byte_mode = 0
        self.packet_mode = 0

        self.byte_standard_deviation = 0
        self.packet_standard_deviation = 0

        self.byte_fisher_skew = 0
        self.packet_fisher_skew = 0

        self.byte_fisher_kurtosis = 0
        self.packet_fisher_kurtosis = 0

        self.byte_correlation = 0
        self.packet_correlation = 0

    def push_front(self, count, val):
        for x in range(count):
            self.byte_count_list.insert(0, val)
            self.packet_count_list.insert(0, val)

    def push_back(self, count, val):
        for x in range(count):
            self.byte_count_list.append(val)
            self.packet_count_list.append(val)

    def pop_front(self, count):
        for x in range(count):
            self.byte_count_list.pop(0)
            self.packet_count_list.pop(0)

    def pop_back(self, count):
        for x in range(count):
            self.byte_count_list.pop()
            self.packet_count_list.pop()

    def delay_start(self):
        if len(self.byte_count_list) < 2:
            return

        first_interval_bytes = self.byte_count_list.pop(0)
        first_interval_packet = self.packet_count_list.pop(0)

        self.byte_count_list[0] = self.byte_count_list[0] + first_interval_bytes
        self.packet_count_list[0] = self.packet_count_list[0] + first_interval_packet

    def is_inactive(self, threshold):
        length = len(self.byte_count_list)
        if length <= threshold:
            return False

        check_index = length - threshold
        while check_index < length:
            if self.byte_count_list[check_index] != 0:
                return False
            check_index = check_index + 1
        return True


class FlowInfoV2:
    def __init__(self, start_interval, data, tcp_threshold, udp_threshold):
        self.start_interval = start_interval
        self.status = STATUS_ACTIVE
        self.match = MatchV2(data)
        self.data = DataV2(data)
        self.pair = None
        self.tcp_finished_flag = False
        if self.match.is_tcp():
            self.threshold = tcp_threshold
        else:
            self.threshold = udp_threshold

    # -----------------------------------------MATCH FUNCTIONS----------------------------------------------------------
    def compare_match_to_entry(self, entry):
        return self.match.compare_match_to_entry(entry)

    def compare_flows(self, other_flow):
        return self.match.compare_match(other_flow.match)

    def get_protocol_name(self):
        return self.match.get_protocol_name()

    def is_dns_communication(self):
        return self.match.is_dns_communication()

    def set_finished(self):
        self.status = STATUS_FINISHED

    def is_active(self):
        return self.status == STATUS_ACTIVE

    def is_waiting(self):
        return self.status == STATUS_WAITING

    def is_finished(self):
        return self.status == STATUS_FINISHED

    def has_pair(self):
        return self.pair is not None

    def set_pair(self, pair):
        self.pair = pair

    def get_pair(self):
        return self.pair

    def create_opposite_entry(self):
        return self.match.create_opposite_entry()

    def to_string_match(self):
        return self.match.to_string()

    def align_tcp_interval_start(self):
        if self.match.is_tcp() and self.pair.match.is_tcp():
            pair_start = self.pair.get_start_interval()
            if self.start_interval == pair_start + 1:
                self.delay_start_interval()
                return

            if self.start_interval == pair_start - 1:
                self.pair.delay_start_interval()
                return

            if self.start_interval < pair_start:
                diff = pair_start - self.start_interval
                self.pair.align_permanently_flow_beginnings(diff)

            if self.start_interval > pair_start:
                diff = self.start_interval - pair_start
                self.align_permanently_flow_beginnings(diff)

    def get_start_interval(self):
        return self.start_interval

    def delay_start_interval(self):
        self.start_interval = self.start_interval + 1
        self.data.delay_start()

    def get_data_lists(self):
        return self.data.get_lists()

    def get_data_lists_length(self):
        byte_list, packet_list = self.data.get_lists()
        return len(byte_list)

    def align_permanently_flow_beginnings(self, count):
        self.start_interval = self.start_interval - count
        self.data.push_front(count, 0)

    def add_front_alignment(self, count):
        self.data.push_front(count, 0)

    def remove_front_alignment(self, count):
        self.data.pop_front(count)

    def add_back_alignment(self, count):
        self.data.push_back(count, 0)

    def remove_back_alignment(self, count):
        self.data.pop_back(count)

    def deactivate_flow(self):
        if self.pair is None:
            self.status = STATUS_FINISHED
        else:
            self.status = STATUS_WAITING

    def has_tcp_finished_flag(self):
        return self.tcp_finished_flag

    def update_counters(self, total_byte_count, total_packet_count):
        if self.status == STATUS_ACTIVE:
            self.data.append_data(total_byte_count, total_packet_count)

    def add_last_tcp_package_data(self, interval, byte_count, packet_count):
        self.set_tcp_finished_flag()
        self.data.add_tcp_flags_data(interval, byte_count, packet_count)

    def set_tcp_finished_flag(self):
        self.tcp_finished_flag = True

    def process_dns(self):
        self.data.append_data(0, 0)
        self.status = STATUS_FINISHED

    def calc_stats(self):
        self.data.calc_self_stats()
        if self.pair is not None:
            self_start_diff, self_end_diff, pair_start_diff, pair_end_diff = self.align_lists()
            pair_byte_list, pair_packet_list = self.pair.get_data_lists()
            self.data.calc_correlation(pair_byte_list, pair_packet_list)
            self.restore_original_lists(self_start_diff, self_end_diff, pair_start_diff, pair_end_diff)

    def align_lists(self):
        self_start_diff = 0
        self_end_diff = 0
        pair_start_diff = 0
        pair_end_diff = 0

        pair_start = self.pair.get_start_interval()

        if self.start_interval < pair_start:
            pair_start_diff = pair_start - self.start_interval
            self.pair.add_front_alignment(pair_start_diff)

        if self.start_interval > pair_start:
            self_start_diff = self.start_interval - pair_start
            self.add_front_alignment(self_start_diff)

        self_list_len = self.get_data_lists_length()
        pair_list_len = self.pair.get_data_lists_length()

        if self_list_len < pair_list_len:
            self_end_diff = pair_list_len - self_list_len
            self.add_back_alignment(self_end_diff)

        if self_list_len > pair_list_len:
            pair_end_diff = self_list_len - pair_list_len
            self.pair.add_back_alignment(pair_end_diff)

        return self_start_diff, self_end_diff, pair_start_diff, pair_end_diff

    def restore_original_lists(self, self_start_diff, self_end_diff, pair_start_diff, pair_end_diff):
        if self_start_diff > 0:
            self.remove_front_alignment(self_start_diff)

        if self_end_diff > 0:
            self.remove_back_alignment(self_end_diff)

        if pair_start_diff > 0:
            self.pair.remove_front_alignment(pair_start_diff)

        if pair_end_diff > 0:
            self.pair.remove_back_alignment(pair_end_diff)

    def add_zeros(self):
        self.data.append_zeros()

    def update_status(self):
        if self.data.is_inactive(self.threshold) or self.tcp_finished_flag:
            self.deactivate_flow()
            self.data.remove_padding()
            if self.get_data_lists_length() < MIN_LENGTH:
                self.data.reset_stats()


# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------TABLE-----------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------


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
        print(config)

    # public
    def on_add_flow(self, info):
        if check_in_marked_flows(info):
            print('Add new flow -> Interval: ' + str(self.interval) + '   Flow: ' + str(info))
        self.add_counter = self.add_counter + 1
        new_flow = FlowInfoV2(self.interval, info, self.tcp_idle_interval, self.udp_idle_interval)
        if new_flow.is_dns_communication():
            self.dns_flows = insert_into_sorted_list(self.dns_flows, new_flow)
            new_flow.process_dns()
        else:
            self.active_flows = insert_into_sorted_list(self.active_flows, new_flow)
        return new_flow

    # public
    def on_update(self, data):
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

        print('Interval:' + str(self.interval) + '   active_flows_size: ' + str(
            len(self.active_flows)) + '   finished_flows_size: ' + str(len(self.finished_flows)))
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
            if check_in_marked_flows(flow.match.get_entry()):
                print('Interval: ' + str(self.interval) + '   Flow: ' + str(flow))

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

    # public
    def on_tcp_flags_package(self, tcp_flow_data):
        index = self.find_active_flow(tcp_flow_data)
        exists = index != -1
        if exists:
            flow = self.active_flows[index]
            if check_in_marked_flows(tcp_flow_data):
                print('TCP flags found -> Interval: ' + str(self.interval) + '   Flow: ' + str(flow))
            flow.add_last_tcp_package_data(self.interval, tcp_flow_data['byte_count'], tcp_flow_data['packet_count'])
        else:
            if check_in_marked_flows(tcp_flow_data):
                print('TCP flags not found -> Interval: ' + str(self.interval) + '   Flow: ' + str(tcp_flow_data))
            new_flow = self.on_add_flow(tcp_flow_data)
            new_flow.set_tcp_finished_flag()

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
        save_active_flows(active_flows_file, self.active_flows, self.finished_flows)
        save_finished_flows(finished_flows_file, self.finished_flows)
        self.clear_finished_flows()

    # public
    def calc_stats(self):
        for flow in self.active_flows:
            flow.calc_stats()

        for flow in self.finished_flows:
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
