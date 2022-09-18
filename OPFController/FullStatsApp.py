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

from flow.storage import init_finished_flows_storage
from flow.table import FlowDataTable
from input import input
from ryu import cfg


import shlex, subprocess

ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3


def extract_data_from_pkt(pkt):
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    if eth.ethertype != ether_types.ETH_TYPE_IP:
        return None

    ip = pkt.get_protocol(ipv4.ipv4)
    protocol = ip.proto

    if protocol == in_proto.IPPROTO_TCP:
        tcp_p = pkt.get_protocol(tcp.tcp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': tcp_p.src_port, 'port_dst': tcp_p.dst_port,
                'protocol_code': in_proto.IPPROTO_TCP, 'byte_count': int(ip.total_length), 'packet_count': 1}
    elif protocol == in_proto.IPPROTO_UDP:
        udp_p = pkt.get_protocol(udp.udp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': udp_p.src_port, 'port_dst': udp_p.dst_port,
                'protocol_code': in_proto.IPPROTO_UDP, 'byte_count': int(ip.total_length), 'packet_count': 1}
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
            data = input.get_statistics()
            self.dataTable.on_update(data)

            self.save_counter = self.save_counter + 1
            if self.save_counter == self.CONF.SAVE_INTERVAL:
                self.save_counter = 0
                self.dataTable.save_flows(self.CONF.ACTIVE_FLOWS_FILE, self.CONF.FINISHED_FLOWS_FILE)

        except subprocess.CalledProcessError as err:
            self.logger.info("Error collecting data")
            self.logger.debug(err)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removal_handler(self, ev):
        flow_data = input.extract_match_data(ev.msg.match)

        # add stats data
        if flow_data is not None:
            flow_data['byte_count'] = ev.msg.stats['byte_count']
            flow_data['packet_count'] = ev.msg.stats['packet_count']
            self.dataTable.on_flow_removed(flow_data)

    @staticmethod
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        data = extract_data_from_pkt(pkt)
        if data:
            if self.is_tcp_flags_packet(pkt, eth):
                # TODO call appropriate method
                pass
            else:
                self.dataTable.on_add_flow(data)
