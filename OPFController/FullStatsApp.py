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
from ryu.lib.packet import in_proto
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu import cfg
import statistics
import scipy.stats

import os
from datetime import datetime
from operator import itemgetter
import shlex, subprocess

ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3

TCP_CODE = 6
UDP_CODE = 17

DNS_PORT = 53
MIN_LENGTH = 2


# -------------------------------------------------PROCESS FLOW DATA----------------------------------------------------


def process_assignment(assignment, flow):
    map_pair = assignment.split('=')

    if map_pair[0] == 'duration':
        flow[map_pair[0]] = map_pair[1]
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
        flow['protocol_code'] = TCP_CODE
    elif part == 'udp':
        flow['protocol_code'] = UDP_CODE

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


def extract_match_data(match):
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


# -------------------------------------------------FLOW INFO------------------------------------------------------------


class FlowInfo:
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
        self.duration = data['duration']

        self.byte_count_list = []
        self.packet_count_list = []

        self.byte_count_list.append(data['byte_count'])
        self.packet_count_list.append(data['packet_count'])

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

    def recalculate_stats(self):
        self.calc_mean()
        self.calc_median()
        self.calc_mode()
        self.calc_standard_deviation()
        self.calc_skew()
        self.calc_kurtosis()
        if self.pair_flow is not None:
            if len(self.byte_count_list) != len(self.pair_flow.byte_count_list):
                self.match_flow_lengths_with_pair()
            self.calc_correlation()

    def perform_final_processing(self, count):
        if self.protocol_code == UDP_CODE:
            del self.byte_count_list[-count:]
            del self.packet_count_list[-count:]
            self.recalculate_stats()

    def is_pair_flow_set(self):
        return self.pair_flow is not None

    def set_pair_flow(self, pair):
        self.pair_flow = pair

    def change_duration(self, duration):
        self.duration = duration

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
        if len(self.byte_count_list) > MIN_LENGTH:
            try:
                self.byte_correlation = scipy.stats.pearsonr(self.byte_count_list, self.pair_flow.byte_count_list)
                self.packet_correlation = scipy.stats.pearsonr(self.packet_count_list, self.pair_flow.packet_count_list)
            except:
                print('Byte list: ' + str(self.byte_count_list))
                print('Pair list: ' + str(self.byte_count_list))
                print('\n\n\n\n\n\n\n\n')
        else:
            self.byte_correlation = 0
            self.packet_correlation = 0

    def match_flow_lengths_with_pair(self):
        if len(self.byte_count_list) < len(self.pair_flow.byte_count_list):
            self.byte_count_list.insert(0, 0)
            self.packet_count_list.insert(0, 0)
        else:
            self.pair_flow.byte_count_list.insert(0, 0)
            self.pair_flow.packet_count_list.insert(0, 0)


# -------------------------------------------------DATA STORAGE---------------------------------------------------------


def stringify_statistics(flow):
    stats = ""
    stats = stats + str(flow.byte_mean) + " "
    stats = stats + str(flow.byte_median) + " "
    stats = stats + str(flow.byte_mode) + " "
    stats = stats + str(flow.byte_standard_deviation) + " "
    stats = stats + str(flow.byte_fisher_skew) + " "
    stats = stats + str(flow.byte_fisher_kurtosis) + " "
    stats = stats + str(flow.byte_correlation) + "\n"

    stats = stats + str(flow.packet_mean) + " "
    stats = stats + str(flow.packet_median) + " "
    stats = stats + str(flow.packet_mode) + " "
    stats = stats + str(flow.packet_standard_deviation) + " "
    stats = stats + str(flow.packet_fisher_skew) + " "
    stats = stats + str(flow.packet_fisher_kurtosis) + " "
    stats = stats + str(flow.packet_correlation) + "\n"
    return stats


def format_flow_info(flow):
    flow_string = ""
    flow_string = flow_string + str(flow.ip_src) + " "
    flow_string = flow_string + str(flow.ip_dst) + " "
    flow_string = flow_string + str(flow.port_src) + " "
    flow_string = flow_string + str(flow.port_dst) + " "
    flow_string = flow_string + str(flow.protocol_code) + "\n"

    flow_string = flow_string + str(flow.total_byte_count) + " "
    flow_string = flow_string + str(flow.total_packet_count) + "\n"

    flow_string = flow_string + str(flow.byte_count_list) + "\n"
    flow_string = flow_string + str(flow.packet_count_list) + "\n"

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
            flow_string = format_flow_info(flow)
            file.write(flow_string)
            file.write("\n")

        file.close()
        return True
    except IOError:
        print("Error saving finished flows")
        return False


# -------------------------------------------------DATA TABLE-----------------------------------------------------------


def is_dns_communication(match):
    return match['protocol_code'] == UDP_CODE and (match['port_src'] == DNS_PORT or match['port_dst'] == DNS_PORT)


def get_dict_match(data):
    return {
        'ip_src': data['ip_src'],
        'ip_dst': data['ip_dst'],
        'port_src': data['port_src'],
        'port_dst': data['port_dst'],
        'protocol_code': data['protocol_code']
    }


class FlowDataTable:
    def __init__(self, udp_interval):
        self.active_flows = []
        self.finished_flows = []
        self.interval = 0
        self.udp_interval = udp_interval

    def push_first_packet_info(self, info):
        info['duration'] = 0
        if is_dns_communication(info):
            new_entry = FlowInfo(start_interval=self.interval, data=info)
            self.finished_flows.append(new_entry)
            new_entry.recalculate_stats()
        else:
            self.insert_active_flow(info)

    def update(self, data):
        self.update_active_flows_table(data)
        self.calc_stats()
        self.separate_finished_flows()

    def update_active_flows_table(self, sorted_data):
        i = 0
        j = 0
        while i < len(sorted_data) and (j < len(self.active_flows)):
            value = self.active_flows[j].compare_match_to_entry(sorted_data[i])

            if value < 0:
                # new flow should be added
                new_entry = FlowInfo(start_interval=self.interval, data=sorted_data[i])
                self.active_flows.insert(j, new_entry)
                i = i + 1
                j = j + 1
            elif value > 0:
                # finished flow, no input for it
                j = j + 1
            else:
                self.active_flows[j].update_counters(sorted_data[i]['byte_count'], sorted_data[i]['packet_count'])
                self.active_flows[j].change_duration(sorted_data[i]['duration'])
                i = i + 1
                j = j + 1

        while i < len(sorted_data):
            new_entry = FlowInfo(start_interval=self.interval, data=sorted_data[i])
            self.active_flows.append(new_entry)
            i = i + 1

        self.interval = self.interval + 1

    def insert_active_flow(self, flow):
        i = 0
        while i < len(self.active_flows) and self.active_flows[i].compare_match_to_entry(flow) == -1:
            i = i + 1
        print('Insert new flow: {' + str(flow['byte_count']) + ', ' + str(flow['packet_count']) + '}\n')
        new_entry = FlowInfo(start_interval=self.interval, data=flow)
        self.active_flows.insert(i, new_entry)

    def find_flow(self, key):
        low = 0
        high = len(self.active_flows) - 1
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

    def find_pair_for_flow(self, flow):
        key = {'ip_src': flow.ip_dst, 'ip_dst': flow.ip_src, 'port_src': flow.port_dst, 'port_dst': flow.port_src,
               'protocol_code': flow.protocol_code}
        index = self.find_flow(key)
        if index != -1:
            return self.active_flows[index]
        return None

    def update_finished_flow(self, finished_flow_data):
        index = self.find_flow(finished_flow_data)

        if index != -1:
            flow = self.active_flows[index]
            flow.update_counters(finished_flow_data['byte_count'], finished_flow_data['packet_count'])
            flow.change_duration(finished_flow_data['duration'])
            flow.finished = True
        else:
            print('Can not find finished flow\n' + str(finished_flow_data))

    def clear_finished_flows(self):
        self.finished_flows = []
        pass

    def calc_stats(self):
        for flow in self.active_flows:
            if not flow.is_pair_flow_set():
                pair = self.find_pair_for_flow(flow)
                if pair is not None:
                    flow.set_pair_flow(pair)
            flow.recalculate_stats()

        print("Stats done")

    def separate_finished_flows(self):
        i = 0
        while i < len(self.active_flows):
            if self.active_flows[i].finished:
                flow = self.active_flows.pop(i)
                self.finished_flows.append(flow)
                flow.perform_final_processing(self.udp_interval)
            else:
                i = i + 1

    def save_flows(self, active_flows_file, finished_flows_file):
        save_active_flows(active_flows_file, self.active_flows)
        save_finished_flows(finished_flows_file, self.finished_flows)
        self.clear_finished_flows()
        print('Saved flows')


# -------------------------------------------------STATS CONTROLLER-----------------------------------------------------
GET_STATISTICS_COMMAND = 'sudo ovs-ofctl -O openflow15 dump-flows s1'


def get_statistics():
    args = shlex.split(GET_STATISTICS_COMMAND)
    output = subprocess.check_output(args, stderr=subprocess.STDOUT)

    return process_flow_data(output)


def extract_data_from_pkt(pkt):
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    if eth.ethertype != ether_types.ETH_TYPE_IP:
        return None

    ip = pkt.get_protocol(ipv4.ipv4)
    protocol = ip.proto

    if protocol == in_proto.IPPROTO_TCP:
        tcp_p = pkt.get_protocol(tcp.tcp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': tcp_p.src_port, 'port_dst': tcp_p.dst_port,
                'protocol_code': TCP_CODE, 'byte_count': int(ip.total_length), 'packet_count': 1}
    elif protocol == in_proto.IPPROTO_UDP:
        udp_p = pkt.get_protocol(udp.udp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': udp_p.src_port, 'port_dst': udp_p.dst_port,
                'protocol_code': UDP_CODE, 'byte_count': int(ip.total_length), 'packet_count': 1}
    return None


class StatsCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StatsCollector, self).__init__(*args, **kwargs)
        self.CONF = cfg.CONF
        self.CONF.register_opts([cfg.IntOpt('IDLE_TIMEOUT_STAT', default=10, help='Idle Timeout for UDP flows')])
        self.CONF.register_opts([cfg.IntOpt('COLLECT_INTERVAL', default=10, help='Interval for collecting stats')])
        self.CONF.register_opts([cfg.IntOpt('SAVE_INTERVAL', default=10, help='Interval for saving data to file')])
        self.CONF.register_opts([cfg.StrOpt('ACTIVE_FLOWS_FILE', default='active_flows.info', help='active flows')])
        self.CONF.register_opts(
            [cfg.StrOpt('FINISHED_FLOWS_FILE', default='finished_flows.info', help='finished flows')])
        self.logger.info("Collect Interval: %d seconds", self.CONF.COLLECT_INTERVAL)
        self.logger.info("Save Interval: %d seconds", self.CONF.SAVE_INTERVAL)
        self.datapath = None
        self.dataTable = FlowDataTable(self.CONF.IDLE_TIMEOUT_STAT)
        self.stats_thread = hub.spawn(self.run)
        self.save_counter = 0
        init_finished_flows_storage(self.CONF.COLLECT_INTERVAL, self.CONF.SAVE_INTERVAL, self.CONF.FINISHED_FLOWS_FILE)

    def run(self):
        while True:
            hub.sleep(self.CONF.COLLECT_INTERVAL)
            if self.datapath is not None:
                parser = self.datapath.ofproto_parser
                req = parser.OFPDescStatsRequest(self.datapath, 0)
                self.datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        try:
            data = get_statistics()
            self.dataTable.update(data)

            self.save_counter = self.save_counter + 1
            if self.save_counter == self.CONF.SAVE_INTERVAL:
                self.save_counter = 0
                self.dataTable.save_flows(self.CONF.ACTIVE_FLOWS_FILE, self.CONF.FINISHED_FLOWS_FILE)

        except subprocess.CalledProcessError as err:
            self.logger.info("Error collecting data")
            self.logger.debug(err)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removal_handler(self, ev):
        flow_data = extract_match_data(ev.msg.match)

        # add stats data
        if flow_data is not None:
            flow_data['byte_count'] = ev.msg.stats['byte_count']
            flow_data['packet_count'] = ev.msg.stats['packet_count']
            flow_data['duration'] = ev.msg.stats['duration']
            self.dataTable.update_finished_flow(flow_data)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        data = extract_data_from_pkt(pkt)
        if data:
            self.dataTable.push_first_packet_info(data)