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

import os
from datetime import datetime
from operator import itemgetter

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
                j = j + 1
            else:
                self.active_flows[j].update_counters(sorted_data[i]['byte_count'], sorted_data[i]['packet_count'])
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

    def finish_flow(self, finished_flow_data):
        index = self.find_active_flow(finished_flow_data)

        if index == -1:
            # flow not in table
            entry = FlowInfo(self.interval, finished_flow_data)
            self.finished_flows.append(entry)
        else:
            flow = self.active_flows.pop(index)
            flow.update_counters(finished_flow_data['byte_count'], finished_flow_data['packet_count'])
            self.finished_flows.append(flow)

    def clear_finished_flows(self):
        self.finished_flows.clear()
        pass

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


ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3


def ofmatch_to_map(match):
    match_map = {'protocol_code': match['ip_proto'], 'ipv4_src': match['ipv4_src'], 'ipv4_dst': match['ipv4_dst']}

    if match['ip_proto'] == in_proto.IPPROTO_TCP:
        match_map['src_port'] = match['tcp_src']
        match_map['dst_port'] = match['tcp_dst']
    elif match['ip_proto'] == in_proto.IPPROTO_UDP:
        match_map['src_port'] = match['udp_src']
        match_map['dst_port'] = match['udp_dst']

    return match_map


def prepare_new_data(body):
    new_data = []
    for flow in body:
        if flow.priority == TCP_UDP_PRIORITY_LEVEL:
            flow_data = ofmatch_to_map(flow.match)
            flow_data['byte_count'] = flow.byte_count
            flow_data['packet_count'] = flow.packet_count
            new_data.append(flow_data)

    new_data.sort(key=itemgetter('ip_src', 'ip_dst', 'port_src', 'port_dst'))

    return new_data


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
                req = parser.OFPFlowStatsRequest(self.datapath)
                self.datapath.send_msg(req)
            hub.sleep(self.CONF.INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removal_handler(self, ev):
        flow_data = ofmatch_to_map(ev.msg.match)
        flow_data['byte_count'] = ev.msg.stats['byte_count']
        flow_data['packet_count'] = ev.msg.stats['packet_count']

        self.dataTable.finish_flow(flow_data)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # filter, reformat and sort new data
        new_data = prepare_new_data(body)

        self.dataTable.update_data(new_data)

        # TODO process data for active and finished flows

        save_flows(self.dataTable.finished_flows)
        self.dataTable.clear_finished_flows()
