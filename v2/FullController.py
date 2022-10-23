# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from ryu import cfg
from ryu.lib import hub

import statistics
import scipy.stats
import shlex
import subprocess
from operator import itemgetter
import os
from datetime import datetime

TABLE_MISS_PRIORITY_LEVEL = 0
ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3

MIN_LENGTH = 2
DNS_PORT = 53

STATUS_ACTIVE = 1
STATUS_WAITING = 2
STATUS_FINISHED = 3

DNS_PORT = 53
ETHERNET_HEADER_SIZE_IN_BYTES = 14


# ------------------------------------------------------DEBUG-----------------------------------------------------------

def match_to_string(match):
    match_str = '{'
    match_str = match_str + 'ip_src: ' + match['ip_src'] + ', '
    match_str = match_str + 'ip_dst: ' + match['ip_dst'] + ', '
    match_str = match_str + 'port_src: ' + str(match['port_src']) + ', '
    match_str = match_str + 'port_dst: ' + str(match['port_dst']) + ', '
    match_str = match_str + 'protocol_code: ' + str(match['protocol_code']) + '} '
    return match_str

# ----------------------------------------------------------------------------------------------------------------------
# ------------------------------------------------------INPUT-----------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------


def process_assignment(assignment, flow):
    map_pair = assignment.split('=')

    if map_pair[0] == 'priority':
        flow[map_pair[0]] = int(map_pair[1])
    if map_pair[0] == 'n_packets':
        flow['packet_count'] = int(map_pair[1])
    if map_pair[0] == 'n_bytes':
        flow['byte_count'] = int(map_pair[1])
    if map_pair[0] == 'nw_src':
        flow['ip_src'] = map_pair[1]
    if map_pair[0] == 'nw_dst':
        flow['ip_dst'] = map_pair[1]
    if map_pair[0] == 'tp_src':
        flow['port_src'] = int(map_pair[1])
    if map_pair[0] == 'tp_dst':
        flow['port_dst'] = int(map_pair[1])

    return flow


def process_part(part, flow):
    if '=' in part:
        flow = process_assignment(part, flow)
    elif part == 'tcp':
        flow['protocol_code'] = in_proto.IPPROTO_TCP
    elif part == 'udp':
        flow['protocol_code'] = in_proto.IPPROTO_UDP

    return flow


def process_line(line):
    flow = {'priority': 0}
    values = line.split(', ')

    for value in values:
        if ' ' in value:
            space_separated_data = value.split(' ')
            for data in space_separated_data:
                if ',' in data:
                    parts = data.split(',')
                    for part in parts:
                        flow = process_part(part, flow)
                else:
                    process_part(data, flow)
        else:
            process_part(value, flow)

    return flow


def process_flow_data(output):
    lines = output.split('\n')
    data = []

    for line in lines:
        flow_info = process_line(line)

        if flow_info['priority'] == TCP_UDP_PRIORITY_LEVEL:
            data.append(flow_info)

    data.sort(key=itemgetter('ip_src', 'ip_dst', 'port_src', 'port_dst'))

    return data


GET_STATISTICS_COMMAND = 'sudo ovs-ofctl -O openflow15 dump-flows s1'


def get_statistics():
    args = shlex.split(GET_STATISTICS_COMMAND)
    output = subprocess.check_output(args, stderr=subprocess.STDOUT)

    return process_flow_data(output)


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

    # flow_string = flow_string + str(flow.total_byte_count) + " "
    # flow_string = flow_string + str(flow.total_packet_count) + "\n"

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


def save_active_flows(file, flows):
    if os.path.exists(file):
        os.remove(file)
    try:
        file = open(file, "w+")
        for flow in flows:
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
        if self.protocol_code == in_proto.IPPROTO_TCP:
            return 'TCP'
        elif self.protocol_code == in_proto.IPPROTO_UDP:
            return 'UDP'
        return 'Not Supported'

    def is_dns_communication(self):
        return self.is_udp() and (self.port_src == DNS_PORT or self.port_dst == DNS_PORT)

    def get_entry(self):
        return {'ip_src': self.ip_src, 'ip_dst': self.ip_dst,
                'port_src': self.port_src, 'port_dst': self.port_dst, 'protocol_code': self.protocol_code}

    def is_tcp(self):
        return self.protocol_code == in_proto.IPPROTO_TCP

    def is_udp(self):
        return self.protocol_code == in_proto.IPPROTO_UDP

    def to_string(self):
        return '{ip_src: ' + self.ip_src + ', ip_dst: ' + self.ip_dst + ', port_src: ' + str(self.port_src) + \
               ', port_dst:' + str(self.port_dst) + '}'


class DataV2:
    # public data -> hash map with byte_count and packet_count
    def __init__(self, data, udp_padding):
        self.additional_bytes = data['byte_count']
        self.additional_packets = data['packet_count']
        self.tcp_flags_interval = -1

        self.previous_byte_count = 0
        self.previous_packet_count = 0
        self.byte_count_list = []
        self.packet_count_list = []

        self.udp_padding = udp_padding

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

    # public - called from tcp flags
    def add_tcp_flags_data(self, interval, byte_count, packet_count):
        self.additional_bytes = byte_count
        self.additional_packets = packet_count
        self.tcp_flags_interval = interval

    def on_tcp_remove_flow(self, interval, total_byte_count, total_packet_count):
        byte_count, packet_count = self.get_interval_values(total_byte_count, total_packet_count)
        byte_count = byte_count + self.additional_bytes
        packet_count = packet_count + self.additional_packets

        if byte_count > 0:
            if interval == self.tcp_flags_interval and len(self.byte_count_list) > 0:
                self.byte_count_list[-1] = self.byte_count_list[-1] + self.additional_bytes + byte_count
                self.packet_count_list[-1] = self.packet_count_list[-1] + self.additional_packets + packet_count
            else:
                self.byte_count_list.append(byte_count)
                self.packet_count_list.append(packet_count)

        self.additional_bytes = 0
        self.additional_packets = 0
        self.previous_byte_count = total_byte_count
        self.previous_packet_count = total_packet_count

    # public - called from removed
    def remove_udp_padding(self):
        # there is no way to byte_count = 0 and packet_count <> 0, we can check only byte_count
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
        self.byte_mode = scipy.stats.mode(self.byte_count_list).mode[0]
        self.packet_mode = scipy.stats.mode(self.packet_count_list).mode[0]

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


class FlowInfoV2:
    def __init__(self, start_interval, data, udp_idle_interval):
        self.start_interval = start_interval
        self.status = STATUS_ACTIVE
        self.match = MatchV2(data)
        self.data = DataV2(data, udp_idle_interval)
        self.udp_idle_interval = udp_idle_interval
        self.pair = None
        self.tcp_finished_flag = False

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

    # -----------------------------------------COUNTERS FUNCTIONS-------------------------------------------------------

    def update_counters(self, total_byte_count, total_packet_count):
        if self.status == STATUS_ACTIVE:
            self.data.append_data(total_byte_count, total_packet_count)

    def add_last_tcp_package_data(self, interval, byte_count, packet_count):
        self.set_tcp_finished_flag()
        self.data.add_tcp_flags_data(interval, byte_count, packet_count)

    def set_tcp_finished_flag(self):
        self.tcp_finished_flag = True

    def on_flow_removed(self, interval, byte_count, packet_count):
        self.deactivate_flow()
        if self.match.is_udp():
            self.data.remove_udp_padding()
            if self.get_data_lists_length() < MIN_LENGTH:
                self.data.reset_stats()
        else:
            self.data.on_tcp_remove_flow(interval, byte_count, packet_count)

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
    def __init__(self, udp_interval):
        self.active_flows = []
        self.finished_flows = []
        self.interval = 0
        self.udp_interval = udp_interval
        self.dns_flows = []
        self.dump_counter = 1

    # public
    def on_add_flow(self, info):
        new_flow = FlowInfoV2(start_interval=self.interval, data=info, udp_idle_interval=self.udp_interval)
        if new_flow.is_dns_communication():
            self.dns_flows = insert_into_sorted_list(self.dns_flows, new_flow)
            new_flow.process_dns()
        else:
            self.active_flows = insert_into_sorted_list(self.active_flows, new_flow)
        return new_flow

    # public
    def on_update(self, data):
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
                if self.active_flows[j].has_tcp_finished_flag() and self.active_flows[j].is_active():
                    self.active_flows[j].deactivate_flow()
                j = j + 1
            else:
                self.active_flows[j].update_counters(sorted_data[i]['byte_count'], sorted_data[i]['packet_count'])
                i = i + 1
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
                if flow.has_tcp_finished_flag():
                    self.finished_flows.append(flow)
                    self.active_flows.pop(i)
                else:
                    i = i + 1

        i = 0
        while i < len(self.finished_flows):
            flow = self.finished_flows[i]
            pair = flow.get_pair()
            if pair is not None:
                if pair.is_waiting() or pair.is_finished():
                    flow.set_finished()
                    pair.set_finished()
            i = i + 1

    # public
    def on_flow_removed(self, removed_flow_data):
        index = self.find_active_flow(removed_flow_data)
        if index != -1:
            flow = self.active_flows[index]
            flow.on_flow_removed(self.interval, removed_flow_data['byte_count'], removed_flow_data['packet_count'])

            self.finished_flows.append(flow)
            self.active_flows.pop(index)
        else:
            index = self.find_dns_flow(removed_flow_data)
            if index != -1:
                self.finished_flows.append(self.dns_flows[index])
                self.dns_flows.pop(index)
            else:
                print('Can not find finished flow\n' + str(removed_flow_data))

    # public
    def on_tcp_flags_package(self, tcp_flow_data):
        print('Table -> TCP flags processing: ' + match_to_string(tcp_flow_data))
        index = self.find_active_flow(tcp_flow_data)
        exists = index != -1
        if exists:
            print('Table -> Found tcp flow: ' + str(tcp_flow_data))
            flow = self.active_flows[index]
            flow.add_last_tcp_package_data(self.interval, tcp_flow_data['byte_count'], tcp_flow_data['packet_count'])
        else:
            # This is the first package in the flow
            new_flow = self.on_add_flow(tcp_flow_data)
            new_flow.set_tcp_finished_flag()
        return exists

    def clear_finished_flows(self):
        # remove all flows marked as finished
        i = 0
        while i < len(self.finished_flows):
            flow = self.finished_flows[i]
            if flow.is_finished():
                self.finished_flows.pop(i)
            else:
                i = i + 1

    # public
    def on_save_flows(self, active_flows_file, finished_flows_file):
        self.calc_stats()
        save_active_flows(active_flows_file, self.active_flows)
        save_finished_flows(finished_flows_file, self.finished_flows)
        save_finished_flows(finished_flows_file, self.dns_flows)
        self.clear_finished_flows()

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

        index = self.find_finish_flow(key)
        if index != -1:
            return self.finished_flows[index]
        return None

    def calc_stats(self):
        for flow in self.active_flows:
            flow.calc_stats()

        for flow in self.finished_flows:
            flow.calc_stats()

    def dump_table(self, flow_str):
        filename = 'table_' + str(self.dump_counter)
        self.dump_counter = self.dump_counter + 1

        file = open(filename, "w+")
        file.write('Flow: ' + flow_str + '\n\n')
        file.write('Table: ' + '\n')
        for flow in self.active_flows:
            file.write(flow.to_string_match())
            file.write("\n")

        file.close()

# ----------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------CONTROLLER--------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------


def extract_match_from_packet(pkt):
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    if eth.ethertype != ether_types.ETH_TYPE_IP:
        return None

    ip = pkt.get_protocol(ipv4.ipv4)
    protocol = ip.proto

    bytes_count = int(ip.total_length) + ETHERNET_HEADER_SIZE_IN_BYTES
    if protocol == in_proto.IPPROTO_TCP:
        tcp_p = pkt.get_protocol(tcp.tcp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': tcp_p.src_port, 'port_dst': tcp_p.dst_port,
                'protocol_code': in_proto.IPPROTO_TCP, 'byte_count': bytes_count, 'packet_count': 1}
    elif protocol == in_proto.IPPROTO_UDP:
        udp_p = pkt.get_protocol(udp.udp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': udp_p.src_port, 'port_dst': udp_p.dst_port,
                'protocol_code': in_proto.IPPROTO_UDP, 'byte_count': bytes_count, 'packet_count': 1}
    return None


def extract_match_data_from_removed_message(match):
    match_map = {'protocol_code': match['ip_proto'], 'ip_src': match['ipv4_src'], 'ip_dst': match['ipv4_dst']}

    if match['ip_proto'] == in_proto.IPPROTO_TCP:
        match_map['port_src'] = match['tcp_src']
        match_map['port_dst'] = match['tcp_dst']
    elif match['ip_proto'] == in_proto.IPPROTO_UDP:
        match_map['port_src'] = match['udp_src']
        match_map['port_dst'] = match['udp_dst']
    else:
        return None

    return match_map


def add_flow(datapath, priority, match, actions, idle_timeout=0, buffer_id=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    cookie = 0
    cookie_mask = 0
    table_id = 0
    hard_timeout = 0
    importance = 0

    if not buffer_id:
        buffer_id = ofproto.OFP_NO_BUFFER

    mod = parser.OFPFlowMod(datapath,
                            cookie,
                            cookie_mask,
                            table_id,
                            ofproto.OFPFC_ADD,
                            idle_timeout,
                            hard_timeout,
                            priority,
                            buffer_id,
                            ofproto.OFPP_ANY,
                            ofproto.OFPG_ANY,
                            ofproto.OFPFF_SEND_FLOW_REM,
                            importance,
                            match,
                            inst)
    datapath.send_msg(mod)


def is_tcp_flags_packet(pkt, eth):
    if eth.ethertype != ether_types.ETH_TYPE_IP:
        return False

    ip = pkt.get_protocol(ipv4.ipv4)
    protocol = ip.proto

    if protocol != in_proto.IPPROTO_TCP:
        return False

    tcp_p = pkt.get_protocol(tcp.tcp)
    tcp_flags = tcp_p.bits

    if tcp_flags & 0x1 or tcp_flags & 0x4:
        return True

    return False


def forward_packet(datapath, msg, in_port, actions):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    data = None
    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        data = msg.data

    match = parser.OFPMatch(in_port=in_port)

    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                              match=match, actions=actions, data=data)
    datapath.send_msg(out)


class SwitchController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchController, self).__init__(*args, **kwargs)
        self.stats_switch = None
        self.mac_to_port = {}

        self.CONF = cfg.CONF
        self.CONF.register_opts([cfg.IntOpt('IDLE_TIMEOUT', default=10, help='Idle Timeout'),
                                 cfg.IntOpt('DELETE_INTERVAL', default=1, help='Delete Interval')])
        self.CONF.register_opts([cfg.IntOpt('COLLECT_INTERVAL', default=10, help='Interval for collecting stats')])
        self.CONF.register_opts([cfg.IntOpt('SAVE_INTERVAL', default=10, help='Interval for saving data to file')])
        self.CONF.register_opts([cfg.StrOpt('ACTIVE_FLOWS_FILE', default='active_flows.info', help='active flows')])
        self.CONF.register_opts(
            [cfg.StrOpt('FINISHED_FLOWS_FILE', default='finished_flows.info', help='finished flows')])
        self.logger.info("Collect Interval: %d seconds", self.CONF.COLLECT_INTERVAL)
        self.logger.info("Save Interval: %d seconds", self.CONF.SAVE_INTERVAL)
        self.logger.info("Idle timeout: %d seconds", self.CONF.IDLE_TIMEOUT)
        self.logger.info("Delete Interval: %d seconds", self.CONF.DELETE_INTERVAL)
        self.logger.info("Active flows file: " + self.CONF.ACTIVE_FLOWS_FILE)
        self.logger.info("Finished flows file: " + self.CONF.FINISHED_FLOWS_FILE)

        self.dataTable = FlowDataTableV2(self.CONF.IDLE_TIMEOUT)
        self.save_counter = 0
        init_finished_flows_storage(self.CONF.COLLECT_INTERVAL, self.CONF.SAVE_INTERVAL, self.CONF.FINISHED_FLOWS_FILE)
        self.stats_thread = hub.spawn(self.run_stats_thread)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # we have only one switch, otherwise change to list
        self.stats_switch = datapath

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        add_flow(datapath, TABLE_MISS_PRIORITY_LEVEL, match, actions)

        # install tcp flags flow entry - we need packet with flags for tcp session end to remove flow from table
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=in_proto.IPPROTO_TCP, tcp_flags=(0x0001 | 0x0004))
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        add_flow(datapath, TCP_FLAGS_PRIORITY_LEVEL, match, actions)

    def get_ethernet_ports(self, datapath, msg, eth):
        ofproto = datapath.ofproto

        in_port = msg.match['in_port']
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        return in_port, out_port

    def process_tcp_flags_packet(self, datapath, pkt, actions, buffer_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        ip = pkt.get_protocol(ipv4.ipv4)
        protocol = ip.proto  # should be 6 - TCP code
        tcp_p = pkt.get_protocol(tcp.tcp)
        match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                 ipv4_src=ip.src,
                                 ipv4_dst=ip.dst,
                                 tcp_src=tcp_p.src_port,
                                 tcp_dst=tcp_p.dst_port,
                                 ip_proto=protocol)

        if buffer_id == ofproto.OFP_NO_BUFFER:
            buffer_id = None

        # Give some time for peers to finish communication and then remove flow from table
        hub.spawn(self.delete_tcp_flow_pair, datapath, match1, actions, buffer_id)

    def delete_tcp_flow_pair(self, datapath, match1, actions, buffer_id=None):
        # wait for session to be closed
        hub.sleep(self.CONF.DELETE_INTERVAL)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        table_id = 0
        hard_timeout = idle_timeout = 0
        priority = TCP_UDP_PRIORITY_LEVEL
        importance = 0
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if not buffer_id:
            buffer_id = ofproto.OFP_NO_BUFFER

        mod = parser.OFPFlowMod(datapath,
                                cookie,
                                cookie_mask,
                                table_id,
                                ofproto.OFPFC_DELETE,
                                idle_timeout,
                                hard_timeout,
                                priority,
                                buffer_id,
                                ofproto.OFPP_ANY,
                                ofproto.OFPG_ANY,
                                ofproto.OFPFF_SEND_FLOW_REM,
                                importance,
                                match1,
                                inst)
        datapath.send_msg(mod)

    def install_flow(self, datapath, msg, pkt, eth, out_port, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check if it is IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                protocol = ip.proto

                match = parser.OFPMatch()
                idle_timeout = 0
                priority = 0

                # Match if not TCP or UDP (for example ICMP protocol)
                if (protocol != in_proto.IPPROTO_TCP) and (protocol != in_proto.IPPROTO_UDP):
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip.src, ipv4_dst=ip.dst,
                                            ip_proto=protocol)
                    priority = ICMP_PRIORITY_LEVEL
                    idle_timeout = self.CONF.IDLE_TIMEOUT
                elif protocol == in_proto.IPPROTO_TCP:
                    tcp_p = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip.src,
                                            ipv4_dst=ip.dst,
                                            tcp_src=tcp_p.src_port,
                                            tcp_dst=tcp_p.dst_port,
                                            ip_proto=protocol)
                    priority = TCP_UDP_PRIORITY_LEVEL
                    idle_timeout = 0
                elif protocol == in_proto.IPPROTO_UDP:
                    udp_p = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip.src,
                                            ipv4_dst=ip.dst,
                                            udp_src=udp_p.src_port,
                                            udp_dst=udp_p.dst_port,
                                            ip_proto=protocol)
                    priority = TCP_UDP_PRIORITY_LEVEL
                    idle_timeout = self.CONF.IDLE_TIMEOUT

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    add_flow(datapath, priority, match, actions, idle_timeout, msg.buffer_id)
                else:
                    add_flow(datapath, priority, match, actions, idle_timeout)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        in_port, out_port = self.get_ethernet_ports(datapath, msg, eth)
        actions = [parser.OFPActionOutput(out_port)]

        if is_tcp_flags_packet(pkt, eth):
            exists = self.save_tcp_flags_packet_info(msg, pkt)
            if not exists:
                self.install_flow(datapath, msg, pkt, eth, out_port, actions)
            self.process_tcp_flags_packet(datapath, pkt, actions, msg.buffer_id)
        else:
            self.install_flow(datapath, msg, pkt, eth, out_port, actions)
            self.add_flow_to_stats_table(msg, pkt)

        forward_packet(datapath, msg, in_port, actions)

    def run_stats_thread(self):
        while True:
            hub.sleep(self.CONF.COLLECT_INTERVAL)
            if self.stats_switch is not None:
                parser = self.stats_switch.ofproto_parser
                req = parser.OFPDescStatsRequest(self.stats_switch, 0)
                self.stats_switch.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        try:
            data = get_statistics()
            self.dataTable.on_update(data)

            self.save_counter = self.save_counter + 1
            if self.save_counter == self.CONF.SAVE_INTERVAL:
                self.save_counter = 0
                self.dataTable.on_save_flows(self.CONF.ACTIVE_FLOWS_FILE, self.CONF.FINISHED_FLOWS_FILE)

        except subprocess.CalledProcessError as err:
            self.logger.info("Error collecting data")
            self.logger.debug(err)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removal_handler(self, ev):
        flow_data = extract_match_data_from_removed_message(ev.msg.match)

        # ipv6 not supported at the moment
        if flow_data is not None:
            flow_data['byte_count'] = ev.msg.stats['byte_count']
            flow_data['packet_count'] = ev.msg.stats['packet_count']
            if flow_data['protocol_code'] == 6:
                print('Removing tcp flow   : ' + match_to_string(flow_data))
            self.dataTable.on_flow_removed(flow_data)

    def save_tcp_flags_packet_info(self, msg, packet):
        data = extract_match_from_packet(packet)
        print('TCP flags processing: ' + match_to_string(data))
        # ipv6 not supported at the moment
        if data is not None:
            data['byte_count'] = msg.total_len
            data['packet_count'] = 1
            return self.dataTable.on_tcp_flags_package(data)
        return True     # ignore this case

    def add_flow_to_stats_table(self, msg, packet):
        data = extract_match_from_packet(packet)

        # ipv6 not supported at the moment
        if data is not None:
            data['byte_count'] = msg.total_len
            data['packet_count'] = 1
            self.dataTable.on_add_flow(data)
