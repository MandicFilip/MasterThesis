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
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from ryu import cfg
from ryu.lib import hub

import requests
import json
import shlex
import subprocess

TABLE_MISS_PRIORITY_LEVEL = 0
ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3

NON_TCP_UDP_PACKET = -1

DNS_PORT = 53


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
    if map_pair[0] == 'ipv6_src':
        flow['ip_src'] = map_pair[1]
    if map_pair[0] == 'nw_dst':
        flow['ip_dst'] = map_pair[1]
    if map_pair[0] == 'ipv6_dst':
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
    elif part == 'tcp6':
        flow['protocol_code'] = in_proto.IPPROTO_TCP
    elif part == 'udp6':
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


def process_stats_data_input(output):
    lines = output.split('\n')
    data = []

    for line in lines:
        flow = process_line(line)

        if flow['priority'] == TCP_UDP_PRIORITY_LEVEL:
            if 'ip_src' in flow and 'ip_dst' in flow and 'port_src' in flow and 'port_dst' in flow and 'protocol_code' in flow and 'byte_count' in flow and 'packet_count' in flow:
                data.append(flow)
            else:
                print('Bad flow -> ' + str(flow))
                print('\nFull line: ' + line + '\n\n')

    return data


GET_STATISTICS_COMMAND = 'sudo ovs-ofctl -O openflow15 dump-flows s1'


def get_statistics():
    args = shlex.split(GET_STATISTICS_COMMAND)
    output = subprocess.check_output(args, stderr=subprocess.STDOUT)

    return process_stats_data_input(output)

# ----------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------DATA BUFFER-------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------


SERVER_URL = 'http://127.0.0.1:8080'
SERVER_ENDPOINT = SERVER_URL + '/flows'

NEW_FLOW_TYPE = 'NEW_FLOW'
TCP_FLAGS_TYPE = 'TCP_FLAGS'

INITIALIZE_SERVER_MESSAGE_TYPE = 'INITIALIZE_SERVER'
UPDATE_MESSAGE_TYPE = 'UPDATE'


class ControllerDataBuffer:
    def __init__(self):
        self.data = []

    def add_initialize_data(self, data):
        del self.data[:]
        data['message_type'] = INITIALIZE_SERVER_MESSAGE_TYPE
        json_data = json.dumps(data)
        requests.post(SERVER_ENDPOINT, json=json_data)

    def add_new_flow_data(self, data):
        data['type'] = NEW_FLOW_TYPE
        self.data.append(data)

    def add_tcp_flags_data(self, data):
        data['type'] = TCP_FLAGS_TYPE
        self.data.append(data)

    def add_stats(self, stats):
        pack = {'update': self.data, 'stats': stats, 'message_type': UPDATE_MESSAGE_TYPE}
        json_pack = json.dumps(pack)
        requests.post(SERVER_ENDPOINT, json=json_pack)
        del self.data[:]


# ----------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------CONTROLLER--------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

class PacketDecoder:
    @staticmethod
    def extract_data_from_IPv4packet(pkt):
        ip = pkt.get_protocol(ipv4.ipv4)
        protocol = ip.proto

        data = {'ip_src': ip.src, 'ip_dst': ip.dst, 'protocol_code': NON_TCP_UDP_PACKET, 'collect': False}
        if protocol == in_proto.IPPROTO_TCP:
            tcp_p = pkt.get_protocol(tcp.tcp)
            data = {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': tcp_p.src_port, 'port_dst': tcp_p.dst_port,
                    'protocol_code': in_proto.IPPROTO_TCP, 'collect': True, 'tcp_flags': tcp_p.bits}
        elif protocol == in_proto.IPPROTO_UDP:
            udp_p = pkt.get_protocol(udp.udp)
            data = {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': udp_p.src_port, 'port_dst': udp_p.dst_port,
                    'protocol_code': in_proto.IPPROTO_UDP, 'collect': True}

        data['ip_version'] = ether_types.ETH_TYPE_IP
        return data

    @staticmethod
    def extract_data_from_IPv6packet(pkt):
        ip = pkt.get_protocol(ipv6.ipv6)
        protocol = ip.nxt

        data = {'ip_src': ip.src, 'ip_dst': ip.dst, 'protocol_code': NON_TCP_UDP_PACKET, 'collect': False}
        if protocol == in_proto.IPPROTO_TCP:
            tcp_p = pkt.get_protocol(tcp.tcp)
            data = {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': tcp_p.src_port, 'port_dst': tcp_p.dst_port,
                    'protocol_code': in_proto.IPPROTO_TCP, 'collect': True, 'tcp_flags': tcp_p.bits}
        elif protocol == in_proto.IPPROTO_UDP:
            udp_p = pkt.get_protocol(udp.udp)
            data = {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': udp_p.src_port, 'port_dst': udp_p.dst_port,
                    'protocol_code': in_proto.IPPROTO_UDP, 'collect': True}
        data['ip_version'] = ether_types.ETH_TYPE_IPV6
        return data

    # public
    def decode_packet(self, msg, pkt):
        data = None
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            data = self.extract_data_from_IPv4packet(pkt)
        elif eth.ethertype == ether_types.ETH_TYPE_IPV6:
            data = self.extract_data_from_IPv6packet(pkt)

        if data is not None:
            data['byte_count'] = msg.total_len
            data['packet_count'] = 1

        return data


def get_transmit_data(data):
    return {'ip_src': data['ip_src'], 'ip_dst': data['ip_dst'], 'port_src': data['port_src'],
            'port_dst': data['port_dst'], 'protocol_code': data['protocol_code'],
            'byte_count': data['byte_count'], 'packet_count': data['packet_count']}


class MatchBuilder:
    @staticmethod
    def build_tcp_ipv4_match(parser, tcp_data):
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ipv4_src=tcp_data['ip_src'],
                               ipv4_dst=tcp_data['ip_dst'],
                               ip_proto=tcp_data['protocol_code'],
                               tcp_src=tcp_data['port_src'],
                               tcp_dst=tcp_data['port_dst'])

    @staticmethod
    def build_udp_ipv4_match(parser, udp_data):
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ipv4_src=udp_data['ip_src'],
                               ipv4_dst=udp_data['ip_dst'],
                               ip_proto=udp_data['protocol_code'],
                               udp_src=udp_data['port_src'],
                               udp_dst=udp_data['port_dst'])

    @staticmethod
    def build_other_ipv4_match(parser, ip_data):
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                               ipv4_src=ip_data['ip_src'],
                               ipv4_dst=ip_data['ip_dst'],
                               ip_proto=ip_data['protocol_code'])

    @staticmethod
    def build_tcp_ipv6_match(parser, tcp_data):
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                               ipv6_src=tcp_data['ip_src'],
                               ipv6_dst=tcp_data['ip_dst'],
                               ip_proto=tcp_data['protocol_code'],
                               tcp_src=tcp_data['port_src'],
                               tcp_dst=tcp_data['port_dst'])

    @staticmethod
    def build_udp_ipv6_match(parser, udp_data):
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                               ipv6_src=udp_data['ip_src'],
                               ipv6_dst=udp_data['ip_dst'],
                               ip_proto=udp_data['protocol_code'],
                               udp_src=udp_data['port_src'],
                               udp_dst=udp_data['port_dst'])

    @staticmethod
    def build_other_ipv6_match(parser, ip_data):
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,
                               ipv6_src=ip_data['ip_src'],
                               ipv6_dst=ip_data['ip_dst'],
                               ip_proto=ip_data['protocol_code'])

    # public
    def build_opf_match(self, parser, data):
        if data['ip_version'] == ether_types.ETH_TYPE_IP:
            if data['protocol_code'] == in_proto.IPPROTO_TCP:
                return self.build_tcp_ipv4_match(parser, data)
            elif data['protocol_code'] == in_proto.IPPROTO_UDP:
                return self.build_udp_ipv4_match(parser, data)
            else:
                return self.build_other_ipv4_match(parser, data)
        else:
            if data['protocol_code'] == in_proto.IPPROTO_TCP:
                return self.build_tcp_ipv6_match(parser, data)
            elif data['protocol_code'] == in_proto.IPPROTO_UDP:
                return self.build_udp_ipv6_match(parser, data)
            else:
                return self.build_other_ipv6_match(parser, data)


class TimeoutManager:
    def __init__(self, tcp_timeout, udp_timeout):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout

    def get_timeout(self, data):
        timeout = self.udp_timeout
        if data['protocol_code'] == in_proto.IPPROTO_TCP:
            timeout = self.tcp_timeout
        return timeout


def get_priority(data):
    priority = ICMP_PRIORITY_LEVEL
    if data['protocol_code'] == in_proto.IPPROTO_TCP or data['protocol_code'] == in_proto.IPPROTO_UDP:
        priority = TCP_UDP_PRIORITY_LEVEL
    return priority


def is_tcp_flags_packet(data):
    if data['protocol_code'] != in_proto.IPPROTO_TCP:
        return False

    is_finished_flag = (data['tcp_flags'] & tcp.TCP_FIN) != 0
    is_reset_flag = (data['tcp_flags'] & tcp.TCP_RST) != 0
    return is_finished_flag or is_reset_flag


def is_dns_communication(data):
    is_udp = data['protocol_code'] == in_proto.IPPROTO_UDP
    return is_udp and (data['port_src'] == DNS_PORT or data['port_dst'] == DNS_PORT)


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
                            0,
                            importance,
                            match,
                            inst)
    datapath.send_msg(mod)


def delete_tcp_flow_pair(datapath, match, actions, sleep, buffer_id):
    # wait for session to be closed
    hub.sleep(sleep)

    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    cookie = cookie_mask = 0
    table_id = 0
    hard_timeout = idle_timeout = 0
    priority = TCP_UDP_PRIORITY_LEVEL
    importance = 0
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

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
                            0,
                            importance,
                            match,
                            inst)
    datapath.send_msg(mod)


def forward_packet(msg, in_port, actions):
    ofproto = msg.datapath.ofproto
    parser = msg.datapath.ofproto_parser

    data = None
    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        data = msg.data

    match = parser.OFPMatch(in_port=in_port)

    out = parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.buffer_id,
                              match=match, actions=actions, data=data)
    msg.datapath.send_msg(out)


class SwitchController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchController, self).__init__(*args, **kwargs)
        self.stats_switch = None
        self.mac_to_port = {}

        self.CONF = cfg.CONF
        self.CONF.register_opts([cfg.IntOpt('TCP_IDLE_TIMEOUT', default=60, help='Idle Timeout')])
        self.CONF.register_opts([cfg.IntOpt('UDP_IDLE_TIMEOUT', default=10, help='Idle Timeout'),
                                 cfg.IntOpt('DELETE_INTERVAL', default=1, help='Delete Interval')])
        self.CONF.register_opts([cfg.FloatOpt('COLLECT_INTERVAL', default=10, help='Interval for collecting stats')])
        self.CONF.register_opts([cfg.IntOpt('SAVE_INTERVAL', default=10, help='Interval for saving data to file')])
        self.CONF.register_opts([cfg.StrOpt('ACTIVE_FLOWS_FILE', default='active_flows.info', help='active flows')])
        self.CONF.register_opts(
            [cfg.StrOpt('FINISHED_FLOWS_FILE', default='finished_flows.info', help='finished flows')])
        self.logger.info("Collect Interval: %f seconds", self.CONF.COLLECT_INTERVAL)
        self.logger.info("Save Interval: %d seconds", self.CONF.SAVE_INTERVAL)
        self.logger.info("Tcp Idle timeout: %d seconds", self.CONF.TCP_IDLE_TIMEOUT)
        self.logger.info("Udp Idle timeout: %d seconds", self.CONF.UDP_IDLE_TIMEOUT)
        self.logger.info("Delete Interval: %d seconds", self.CONF.DELETE_INTERVAL)
        self.logger.info("Active flows file: " + self.CONF.ACTIVE_FLOWS_FILE)
        self.logger.info("Finished flows file: " + self.CONF.FINISHED_FLOWS_FILE)
        self.stats_thread = hub.spawn(self.run_stats_thread)
        self.controller_data_buffer = ControllerDataBuffer()
        self.packet_decoder = PacketDecoder()
        self.match_builder = MatchBuilder()
        self.timeout_manager = TimeoutManager(self.CONF.TCP_IDLE_TIMEOUT, self.CONF.UDP_IDLE_TIMEOUT)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # we have only one switch, otherwise change to list
        self.stats_switch = datapath

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        add_flow(datapath, TABLE_MISS_PRIORITY_LEVEL, match, actions)

        # install tcp flags flow entry - we need packet with flags for tcp session end to remove flow from table
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                                tcp_flags=(tcp.TCP_FIN | tcp.TCP_RST))
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        add_flow(datapath, TCP_FLAGS_PRIORITY_LEVEL, match, actions)

        # maybe not needed
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ip_proto=in_proto.IPPROTO_TCP,
                                tcp_flags=(tcp.TCP_FIN | tcp.TCP_RST))
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        add_flow(datapath, TCP_FLAGS_PRIORITY_LEVEL, match, actions)

        data = {'collect_interval': self.CONF.COLLECT_INTERVAL,
                'save_interval': int(round(self.CONF.SAVE_INTERVAL / self.CONF.COLLECT_INTERVAL)),
                'tcp_idle_interval': int(round(self.CONF.TCP_IDLE_TIMEOUT / self.CONF.COLLECT_INTERVAL)),
                'udp_idle_interval': int(round(self.CONF.UDP_IDLE_TIMEOUT / self.CONF.COLLECT_INTERVAL)),
                'active_flows_file': self.CONF.ACTIVE_FLOWS_FILE,
                'finished_flows_file': self.CONF.FINISHED_FLOWS_FILE
                }
        self.controller_data_buffer.add_initialize_data(data)

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

    # -----------------------------ABOVE: fixed for IPv6----------------------------------------------------------------
    def schedule_flow_removal(self, msg, data, actions):
        parser = msg.datapath.ofproto_parser

        match = self.match_builder.build_opf_match(parser, data)

        # Give some time for peers to finish communication and then remove flow from table
        hub.spawn(delete_tcp_flow_pair, msg.datapath, match, actions, self.CONF.DELETE_INTERVAL, msg.buffer_id)

    def install_flow(self, data, msg, actions):
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser

        match = self.match_builder.build_opf_match(parser, data)
        priority = get_priority(data)
        idle_timeout = self.timeout_manager.get_timeout(data)

        # verify if we have a valid buffer_id, if yes avoid to send both
        # flow_mod & packet_out
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            add_flow(msg.datapath, priority, match, actions, idle_timeout, msg.buffer_id)
        else:
            add_flow(msg.datapath, priority, match, actions, idle_timeout)

    def process_data(self, data, msg, actions):
        if is_tcp_flags_packet(data):
            if msg.reason == ofproto_v1_5.OFPR_TABLE_MISS:
                self.install_flow(data, msg, actions)
            self.schedule_flow_removal(msg, data, actions)
            self.save_tcp_flags_packet_to_table(data)
        else:
            if not is_dns_communication(data):
                self.install_flow(data, msg, actions)
            self.add_flow_to_stats_table(data)

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
        in_port, out_port = self.get_ethernet_ports(datapath, msg, eth)
        actions = [parser.OFPActionOutput(out_port)]

        data = self.packet_decoder.decode_packet(msg, pkt)
        if data is not None:
            self.process_data(data, msg, actions)
        else:
            print(pkt)
            print('\n')

        forward_packet(msg, in_port, actions)

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
            self.controller_data_buffer.add_stats(data)

        except subprocess.CalledProcessError as err:
            self.logger.info("Error collecting data")
            self.logger.debug(err)

    def save_tcp_flags_packet_to_table(self, data):
        transmit_data = get_transmit_data(data)
        self.controller_data_buffer.add_tcp_flags_data(transmit_data)

    def add_flow_to_stats_table(self, data):
        if data['collect']:
            transmit_data = get_transmit_data(data)
            self.controller_data_buffer.add_new_flow_data(transmit_data)
