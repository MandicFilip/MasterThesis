from ryu.ryu.lib.packet import in_proto
import statistics
import scipy.stats

MIN_LENGTH = 2
DNS_PORT = 53

STATUS_CREATED = 1
STATUS_ACTIVE = 2
STATUS_LOST_PAIR = 3
STATUS_FIN_FLAG = 4
STATUS_FINISHED = 5


class FlowInfo:
    def __init__(self, start_interval, data, udp_idle_interval):
        self.start_interval = start_interval
        self.status = STATUS_CREATED
        self.ip_src = data['ip_src']
        self.ip_dst = data['ip_dst']
        self.port_src = data['port_src']
        self.port_dst = data['port_dst']
        self.protocol_code = data['protocol_code']
        self.first_flooded_byte_count = data['byte_count']
        self.first_flooded_packet_count = data['packet_count']
        self.last_flooded_byte_count = 0
        self.last_flooded_packet_count = 0

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

        self.pair_flow = None
        self.byte_correlation = 0
        self.packet_correlation = 0

        self.front_padding = 0
        self.backPadding = 0
        self.udp_idle_interval = udp_idle_interval

    def finish(self):
        self.status = STATUS_FINISHED

    def is_finished(self):
        return self.status == STATUS_FINISHED

    def is_active(self):
        return self.status == STATUS_ACTIVE

    def is_pair_flow_set(self):
        return self.pair_flow is not None

    def set_pair_flow(self, pair):
        self.pair_flow = pair

    def remove_pair_flow(self):
        self.pair_flow = None
        self.status = STATUS_LOST_PAIR

    def get_protocol_name(self):
        if self.protocol_code == in_proto.IPPROTO_TCP:
            return 'TCP'
        elif self.protocol_code == in_proto.IPPROTO_UDP:
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

    def compare_flows(self, other_flow):
        match = {'ip_src': other_flow.ip_src, 'ip_dst': other_flow.ip_dst,
                 'port_src': other_flow.port_src, 'port_dst': other_flow.port_dst}
        return self.compare_match_to_entry(match)

    def update_counters(self, byte_count, packet_count):
        if self.status == STATUS_CREATED:
            diff_byte_count = byte_count + self.first_flooded_byte_count
            diff_packet_count = packet_count + self.first_flooded_packet_count
            self.add_new_bytes_and_packages(diff_byte_count, diff_packet_count)
            self.status = STATUS_ACTIVE

        if self.status == STATUS_ACTIVE or self.status == STATUS_LOST_PAIR:
            diff_byte_count = byte_count + self.first_flooded_byte_count + self.last_flooded_byte_count - self.total_byte_count
            diff_packet_count = packet_count + self.first_flooded_packet_count + self.last_flooded_packet_count - self.total_packet_count
            self.add_new_bytes_and_packages(diff_byte_count, diff_packet_count)

        if self.status == STATUS_FINISHED:

            pass

    def add_new_bytes_and_packages(self, diff_byte_count, diff_packet_count):
        self.total_byte_count = self.total_byte_count + diff_byte_count
        self.total_packet_count = self.total_packet_count + diff_packet_count
        self.byte_count_list.append(diff_byte_count)
        self.packet_count_list.append(diff_packet_count)

    def add_fin_flag_data(self, byte_count, packet_count):
        self.total_byte_count = self.total_byte_count + byte_count
        self.total_packet_count = self.total_packet_count + packet_count
        if len(self.byte_count_list) == 0:
            self.byte_count_list.append(0)
        self.byte_count_list[-1] = self.byte_count_list[-1] + byte_count

        if len(self.packet_count_list) == 0:
            self.packet_count_list.append(0)
        self.packet_count_list[-1] = self.packet_count_list[-1] + packet_count

    def recalculate_stats(self):
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
        self.byte_mode = scipy.stats.mode(self.byte_count_list).mode[0]
        self.packet_mode = scipy.stats.mode(self.packet_count_list).mode[0]

    def calc_standard_deviation(self):
        if len(self.byte_count_list) > MIN_LENGTH:
            self.byte_standard_deviation = statistics.stdev(self.byte_count_list)
            self.packet_standard_deviation = statistics.stdev(self.packet_count_list)
        else:
            self.byte_standard_deviation = 0
            self.packet_standard_deviation = 0

    def calc_skew(self):
        self.byte_fisher_skew = scipy.stats.skew(self.byte_count_list)
        self.packet_fisher_skew = scipy.stats.skew(self.packet_count_list)

    def calc_kurtosis(self):
        if len(self.byte_count_list) > MIN_LENGTH:
            self.byte_fisher_kurtosis = scipy.stats.kurtosis(self.byte_count_list)
            self.packet_fisher_kurtosis = scipy.stats.kurtosis(self.packet_count_list)
        else:
            self.byte_fisher_kurtosis = 0
            self.packet_fisher_kurtosis = 0

    def calc_correlation(self):
        if self.is_pair_flow_set() and self.status == STATUS_ACTIVE:
            if len(self.byte_count_list) != len(self.pair_flow.byte_count_list):
                self.match_flow_lengths_with_pair()

            if len(self.byte_count_list) > MIN_LENGTH:
                try:
                    self.byte_correlation = scipy.stats.pearsonr(self.byte_count_list, self.pair_flow.byte_count_list)
                    self.packet_correlation = scipy.stats.pearsonr(self.packet_count_list,
                                                                   self.pair_flow.packet_count_list)
                except:
                    print('Byte list: ' + str(self.byte_count_list))
                    print('Pair list: ' + str(self.byte_count_list))
                    print('\n\n\n')
            else:
                self.byte_correlation = 0
                self.packet_correlation = 0

    def match_flow_lengths_with_pair(self):
        if len(self.byte_count_list) < len(self.pair_flow.byte_count_list):
            self.add_front_padding()
        else:
            self.pair_flow.add_front_padding()

    def add_front_padding(self):
        self.byte_count_list.insert(0, 0)
        self.packet_count_list.insert(0, 0)
        self.front_padding = self.front_padding + 1

    def add_back_padding(self):
        self.byte_count_list.append(0)
        self.packet_count_list.append(0)
        self.backPadding = self.backPadding + 1

    def remove_front_padding(self):
        self.byte_count_list = self.byte_count_list[self.front_padding:]
        self.packet_count_list = self.packet_count_list[self.front_padding:]
        self.front_padding = 0

    def remove_back_padding(self):
        del self.byte_count_list[-self.backPadding:]
        del self.packet_count_list[-self.backPadding:]
        self.backPadding = 0

    def remove_udp_padding(self):
        if self.protocol_code == in_proto.IPPROTO_UDP:
            del self.byte_count_list[-self.udp_idle_interval:]
            del self.packet_count_list[-self.udp_idle_interval:]

    def perform_final_processing(self):
        self.remove_front_padding()
        self.remove_back_padding()
        self.recalculate_stats()
        if self.is_pair_flow_set():
            self.pair_flow.set_pair_flow(None)
            self.pair_flow = None

    def is_dns_communication(self):
        return self.protocol_code == in_proto.IPPROTO_UDP and (self.port_src == DNS_PORT or self.port_dst == DNS_PORT)
