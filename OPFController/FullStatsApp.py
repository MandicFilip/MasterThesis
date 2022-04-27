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
from ryu.lib.packet import in_proto
from ryu.lib import hub
from ryu import cfg
import statistics
import scipy

import os
from datetime import datetime
from operator import itemgetter
import shlex, subprocess

ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3

TCP_CODE = 6
UDP_CODE = 17

MIN_LENGTH = 3

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
    print(match)

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
        if len(self.byte_count_list) > MIN_LENGTH:
            self.calc_mean()
            self.calc_median()
            self.calc_mode()
            self.calc_standard_deviation()
            self.calc_skew()
            self.calc_kurtosis()

            if len(self.byte_count_list) != len(self.pair_flow.byte_count_list):
                self.match_flow_lengths_with_pair()
            self.calc_correlation()

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
        self.byte_mode = statistics.mode(self.byte_count_list)
        self.packet_mode = statistics.mode(self.packet_count_list)

    def calc_standard_deviation(self):
        self.byte_standard_deviation = statistics.stdev(self.byte_count_list)
        self.packet_standard_deviation = statistics.stdev(self.packet_count_list)

    def calc_skew(self):
        self.byte_fisher_skew = scipy.stats.skew(self.byte_count_list)
        self.packet_fisher_skew = scipy.stats.skew(self.packet_count_list)

    def calc_kurtosis(self):
        self.byte_fisher_kurtosis = scipy.stats.kurtosis(self.byte_count_list)
        self.packet_fisher_kurtosis = scipy.stats.kurtosis(self.packet_count_list)

    def calc_correlation(self):
        if self.pair_flow is not None:
            self.byte_correlation = scipy.stats.pearsonr(self.byte_count_list, self.pair_flow.byte_count_list)
            self.packet_correlation = scipy.stats.pearsonr(self.packet_count_list, self.pair_flow.packet_count_list)

    def match_flow_lengths_with_pair(self):
        if len(self.byte_count_list) < len(self.pair_flow.byte_count_list):
            self.byte_count_list.insert(0, 0)
            self.packet_count_list.insert(0, 0)
        else:
            self.pair_flow.byte_count_list.insert(0, 0)
            self.pair_flow.packet_count_list.insert(0, 0)

# -------------------------------------------------DATA TABLE-----------------------------------------------------------


def get_dict_match(data):
    return {
        'ip_src': data['ip_src'],
        'ip_dst': data['ip_dst'],
        'port_src': data['port_src'],
        'port_dst': data['port_dst'],
        'protocol_code': data['protocol_code']
    }


class FlowDataTable:
    def __init__(self):
        self.active_flows = []
        self.finished_flows = []
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

    def find_active_flow(self, key):
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

    def find_active_pair_for_flow(self, flow):
        key = flow
        key['ip_src'] = flow['ip_dst']
        key['ip_dst'] = flow['ip_src']
        key['port_src'] = flow['port_dst']
        key['port_dst'] = flow['port_src']
        key['protocol_code'] = flow['protocol_code']
        index = self.find_active_flow(key)
        if index != -1:
            return self.active_flows[index]
        return None

    def finish_flow(self, finished_flow_data):
        index = self.find_active_flow(finished_flow_data)

        if index != -1:
            flow = self.active_flows.pop(index)
            flow.update_counters(finished_flow_data['byte_count'], finished_flow_data['packet_count'])
            flow.change_duration(finished_flow_data['duration'])
            self.finished_flows.append(flow)

    def clear_finished_flows(self):
        self.finished_flows.clear()
        pass

    def calc_stats(self):
        for flow in self.active_flows:
            if not flow.is_pair_flow_set():
                pair = self.find_active_pair_for_flow(flow)
                if pair is not None:
                    flow.set_pair_flow(pair)
            flow.recalculate_stats()

        print("Stats done")


# -------------------------------------------------DATA STORAGE---------------------------------------------------------


file_name = "finished_flows.info"


def init_storage(interval_length):
    if os.path.exists(file_name):
        os.remove(file_name)

    try:
        file = open(file_name, "w+")

        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        file.write(current_time + "\n")

        file.write("Interval length: " + str(interval_length) + "\n\n")

        file.close()
    except IOError:
        print("Error opening file!")
    pass


def format_flow_info(flow):
    flow_string = ""
    flow_string = flow_string + flow.ip_src + " "
    flow_string = flow_string + flow.ip_dst + " "
    flow_string = flow_string + flow.port_src + " "
    flow_string = flow_string + flow.port_dst + " "
    flow_string = flow_string + flow.protocol_code + " "

    flow_string = flow_string + "\n"

    flow_string = flow_string + flow.total_byte_count + " " + flow.total_packet_count + "\n"

    flow_string = flow_string + flow_string(flow.byte_count_list) + "\n"
    flow_string = flow_string + flow_string(flow.packet_count_list) + "\n"

    # TODO save stats when calculated

    return flow_string


def save_to_file(finished_flows, file):
    for flow in finished_flows:
        flow_string = format_flow_info(flow)
        file.write(flow_string)
        file.write("\n")


def save_flows(finished_flows):
    if not os.path.exists(file_name):
        print("Error with file")
        return False
    try:
        file = open(file_name, "a")
        save_to_file(finished_flows, file)
        file.close()
        return True
    except IOError:
        print("Error saving finished flows")
        return False


# -------------------------------------------------STATS CONTROLLER-----------------------------------------------------


class StatsCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StatsCollector, self).__init__(*args, **kwargs)
        self.CONF = cfg.CONF
        self.CONF.register_opts([cfg.IntOpt('INTERVAL', default=10, help='Interval for collecting stats')])
        self.logger.info("Interval: %d seconds", self.CONF.INTERVAL)
        self.datapath = None
        self.dataTable = FlowDataTable()
        init_storage(self.CONF.INTERVAL)
        self.stats_thread = hub.spawn(self.run)

    def run(self):
        print("Collection start")
        hub.sleep(self.CONF.INTERVAL)
        while True:
            if self.datapath is not None:
                parser = self.datapath.ofproto_parser
                req = parser.OFPDescStatsRequest(self.datapath, 0)
                self.datapath.send_msg(req)

                # TODO counting for saving data to file

            hub.sleep(self.CONF.INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        command = 'sudo ovs-ofctl -O openflow15 dump-flows s1'
        try:
            args = shlex.split(command)
            output = subprocess.check_output(args, stderr=subprocess.STDOUT)

            data = process_flow_data(output)

            self.dataTable.update_data(data)
            self.dataTable.calc_stats()
            # TODO process data for active and finished flows (done flag)

            print(self.dataTable.active_flows)
            print(self.dataTable.finished_flows)
            # save_flows(self.dataTable.finished_flows)
            # self.dataTable.clear_finished_flows()

        except subprocess.CalledProcessError as err:
            self.logger.info("Error collecting data")
            self.logger.debug(err)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removal_handler(self, ev):
        flow_data = extract_match_data(ev.msg.match)

        if flow_data is not None:
            flow_data['byte_count'] = ev.msg.stats['byte_count']
            flow_data['packet_count'] = ev.msg.stats['packet_count']
            flow_data['duration'] = ev.msg.stats['duration']

            self.dataTable.finish_flow(flow_data)
