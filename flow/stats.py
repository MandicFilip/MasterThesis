import statistics
import scipy.stats

MIN_LENGTH = 2

# Previous byte and packet count doesn't include establish flow info - they are just here to speed up calculating
# data size in last interval

# Reseno azuriranje usled prvog i poslednjeg (kod tcp-a) paketa


class FlowStats:
    # public data -> hash map with byte_count and packet_count
    def __init__(self, data):
        self.establish_flow_byte_count = data['byte_count']
        self.establish_flow_packet_count = data['packet_count']
        self.finish_connection_byte_count = 0
        self.finish_connection_packet_count = 0

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

        self.udp_padding = 0

    # public
    def append_data(self, byte_count, packet_count):
        self.byte_count_list.append(byte_count)
        if len(self.byte_count_list) == 1:
            self.byte_count_list[0] = self.byte_count_list[0] + self.establish_flow_byte_count

        self.packet_count_list.append(packet_count)
        if len(self.packet_count_list) == 1:
            self.packet_count_list[0] = self.packet_count_list[0] + self.establish_flow_packet_count

        self.previous_byte_count = self.previous_byte_count + byte_count
        self.previous_packet_count = self.previous_packet_count + packet_count

    # public
    def add_tcp_finish_data(self, byte_count, packet_count):
        if len(self.byte_count_list) > 0:
            self.byte_count_list[-1] = self.byte_count_list[-1] + byte_count
        else:
            self.byte_count_list.append(self.establish_flow_byte_count + byte_count)

        if len(self.packet_count_list) > 0:
            self.packet_count_list[-1] = self.packet_count_list[-1] + packet_count
        else:
            self.packet_count_list.append(self.establish_flow_packet_count + packet_count)

    # public
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
