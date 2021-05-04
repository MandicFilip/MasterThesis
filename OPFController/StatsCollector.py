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
from operator import itemgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import in_proto
from ryu.lib import hub
from ryu import cfg

from dataryu.FlowDataTable import FlowDataTable
from dataryu.DataStorage import save_flows, init_storage

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
        self.stats_thread = hub.spawn(self.run)
        self.dataTable = FlowDataTable()
        init_storage(self.CONF.INTERVAL)

    def run(self):
        print("Collection start")
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
