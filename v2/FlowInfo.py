import statistics
import scipy.stats

TCP_PROTOCOL_CODE = 6
UDP_PROTOCOL_CODE = 17
DNS_PORT = 53

MIN_LENGTH = 2

STATUS_ACTIVE = 1
STATUS_WAITING = 2
STATUS_FINISHED = 3

# ----------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------FLOW-----------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------


class Match:
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
               ', port_dst:' + str(self.port_dst) + ', protocol_code' + str(self.protocol_code) + '}'

    def get_file_output_string(self):
        match_string = ""
        match_string = match_string + str(self.ip_src) + " "
        match_string = match_string + str(self.ip_dst) + " "
        match_string = match_string + str(self.port_src) + " "
        match_string = match_string + str(self.port_dst) + " "
        match_string = match_string + str(self.protocol_code) + "\n"
        return match_string


class Data:
    # public data -> hash map with byte_count and packet_count
    def __init__(self, data):
        self.additional_bytes = data['byte_count']
        self.additional_packets = data['packet_count']
        self.tcp_flags_interval = -1

        self.stats_report_byte_count = 0
        self.stats_report_packet_count = 0
        self.total_byte_count = 0
        self.total_packet_count = 0
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
    def append_data(self, current_byte_count, current_packet_count):
        byte_count, packet_count = self.get_interval_values(current_byte_count, current_packet_count)

        byte_count = byte_count + self.additional_bytes
        packet_count = packet_count + self.additional_packets

        self.byte_count_list.append(byte_count)
        self.packet_count_list.append(packet_count)

        self.total_byte_count = self.total_byte_count + byte_count
        self.total_packet_count = self.total_packet_count + packet_count

        self.stats_report_byte_count = current_byte_count
        self.stats_report_packet_count = current_packet_count

        self.additional_bytes = 0
        self.additional_packets = 0

    def append_zeros(self):
        self.append_data(self.stats_report_byte_count, self.stats_report_packet_count)

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
        byte_count = total_byte_count - self.stats_report_byte_count
        packet_count = total_packet_count - self.stats_report_packet_count
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

    def get_file_output_string_for_basic_stats(self, start_interval, current_interval):
        output = ""
        output = output + str(current_interval - start_interval) + " "
        output = output + str(self.total_byte_count) + " "
        output = output + str(self.total_packet_count) + "\n"
        return output

    def get_file_output_string_for_advanced_stats(self):
        output = ""
        output = output + str(self.byte_mean) + " "
        output = output + str(self.byte_median) + " "
        output = output + str(self.byte_mode) + " "
        output = output + str(self.byte_standard_deviation) + " "
        output = output + str(self.byte_fisher_skew) + " "
        output = output + str(self.byte_fisher_kurtosis) + " "
        output = output + str(self.byte_correlation) + "\n"
        output = output + str(self.packet_mean) + " "
        output = output + str(self.packet_median) + " "
        output = output + str(self.packet_mode) + " "
        output = output + str(self.packet_standard_deviation) + " "
        output = output + str(self.packet_fisher_skew) + " "
        output = output + str(self.packet_fisher_kurtosis) + " "
        output = output + str(self.packet_correlation) + "\n"
        return output

    def get_file_output_string_for_arrays(self):
        output = ""
        output = output + str(self.byte_count_list) + "\n"
        output = output + str(self.packet_count_list) + "\n"
        return output


class FlowInfo:
    def __init__(self, start_interval, data, tcp_threshold, udp_threshold):
        self.start_interval = start_interval
        self.status = STATUS_ACTIVE
        self.match = Match(data)
        self.data = Data(data)
        self.pair = None
        self.tcp_finished_flag = False
        if self.match.is_tcp():
            self.threshold = tcp_threshold
        else:
            self.threshold = udp_threshold

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

    def get_file_output_string(self, current_interval, include_advanced_stats, include_arrays):
        flow_string = ""
        flow_string = flow_string + self.match.get_file_output_string()
        flow_string = flow_string + self.data.get_file_output_string_for_basic_stats(self.start_interval, current_interval)
        if include_advanced_stats:
            flow_string = flow_string + self.data.get_file_output_string_for_advanced_stats()
        if include_arrays:
            flow_string = flow_string + self.data.get_file_output_string_for_arrays()
        return flow_string
