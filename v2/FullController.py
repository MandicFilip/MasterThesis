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

import requests
import json
import shlex
import subprocess

TABLE_MISS_PRIORITY_LEVEL = 0
ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3

DNS_PORT = 53

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

    return data


GET_STATISTICS_COMMAND = 'sudo ovs-ofctl -O openflow15 dump-flows s1'


def get_statistics():
    args = shlex.split(GET_STATISTICS_COMMAND)
    output = subprocess.check_output(args, stderr=subprocess.STDOUT)

    return process_flow_data(output)


# ----------------------------------------------------------------------------------------------------------------------
# ----------------------------------------------------CONTROLLER--------------------------------------------------------
# ----------------------------------------------------------------------------------------------------------------------

# CONTROLLER
def extract_match_from_packet(pkt):
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    if eth.ethertype != ether_types.ETH_TYPE_IP:
        return None

    ip = pkt.get_protocol(ipv4.ipv4)
    protocol = ip.proto

    if protocol == in_proto.IPPROTO_TCP:
        tcp_p = pkt.get_protocol(tcp.tcp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': tcp_p.src_port, 'port_dst': tcp_p.dst_port,
                'protocol_code': in_proto.IPPROTO_TCP}
    elif protocol == in_proto.IPPROTO_UDP:
        udp_p = pkt.get_protocol(udp.udp)
        return {'ip_src': ip.src, 'ip_dst': ip.dst, 'port_src': udp_p.src_port, 'port_dst': udp_p.dst_port,
                'protocol_code': in_proto.IPPROTO_UDP}
    return None


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


def is_tcp_flags_packet(pkt, eth):
    if eth.ethertype != ether_types.ETH_TYPE_IP:
        return False

    ip = pkt.get_protocol(ipv4.ipv4)
    protocol = ip.proto

    if protocol != in_proto.IPPROTO_TCP:
        return False

    tcp_p = pkt.get_protocol(tcp.tcp)
    tcp_flags = tcp_p.bits

    if tcp_flags & tcp.TCP_FIN or tcp_flags & tcp.TCP_RST:
        return True

    return False


def is_dns_communication(data):
    is_udp = data['protocol_code'] == in_proto.IPPROTO_UDP
    return is_udp and (data['port_src'] == DNS_PORT or data['port_dst'] == DNS_PORT)


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


SERVER_URL = 'http://127.0.0.1:8080'
UPDATE_ENDPOINT = SERVER_URL + '/update'
INITIALIZE_SERVER_ENDPOINT = SERVER_URL + '/initialize'

NEW_FLOW_TYPE = 'NEW_FLOW'
TCP_FLAGS_TYPE = 'TCP_FLAGS'


class ControllerDataBuffer:
    def __init__(self):
        self.data = []

    def add_initialize_data(self, data):
        self.data.clear()
        json_data = json.dumps(data)
        requests.post(INITIALIZE_SERVER_ENDPOINT, json=json_data)

    def add_new_flow_data(self, data):
        data['type'] = NEW_FLOW_TYPE
        self.data.append(data)

    def add_tcp_flags_data(self, data):
        data['type'] = TCP_FLAGS_TYPE
        self.data.append(data)

    def add_stats(self, stats):
        pack = {'update': self.data, 'stats:': stats}
        json_pack = json.dumps(pack)
        requests.post(UPDATE_ENDPOINT, json=json_pack)
        self.data.clear()


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
        self.CONF.register_opts([cfg.IntOpt('COLLECT_INTERVAL', default=10, help='Interval for collecting stats')])
        self.CONF.register_opts([cfg.IntOpt('SAVE_INTERVAL', default=10, help='Interval for saving data to file')])
        self.CONF.register_opts([cfg.StrOpt('ACTIVE_FLOWS_FILE', default='active_flows.info', help='active flows')])
        self.CONF.register_opts(
            [cfg.StrOpt('FINISHED_FLOWS_FILE', default='finished_flows.info', help='finished flows')])
        self.logger.info("Collect Interval: %d seconds", self.CONF.COLLECT_INTERVAL)
        self.logger.info("Save Interval: %d seconds", self.CONF.SAVE_INTERVAL)
        self.logger.info("Tcp Idle timeout: %d seconds", self.CONF.TCP_IDLE_TIMEOUT)
        self.logger.info("Udp Idle timeout: %d seconds", self.CONF.UDP_IDLE_TIMEOUT)
        self.logger.info("Delete Interval: %d seconds", self.CONF.DELETE_INTERVAL)
        self.logger.info("Active flows file: " + self.CONF.ACTIVE_FLOWS_FILE)
        self.logger.info("Finished flows file: " + self.CONF.FINISHED_FLOWS_FILE)
        self.stats_thread = hub.spawn(self.run_stats_thread)
        self.controller_data_buffer = ControllerDataBuffer()

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
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                                tcp_flags=(tcp.TCP_FIN | tcp.TCP_RST))
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        add_flow(datapath, TCP_FLAGS_PRIORITY_LEVEL, match, actions)

        data = {'collect_interval': self.CONF.COLLECT_INTERVAL, 'save_interval': self.CONF.SAVE_INTERVAL,
                'tcp_idle_interval': self.CONF.TCP_IDLE_TIMEOUT, 'udp_idle_interval': self.CONF.UDP_IDLE_TIMEOUT,
                'active_flows_file': self.CONF.ACTIVE_FLOWS_FILE, 'finished_flows_file': self.CONF.FINISHED_FLOWS_FILE}
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

    def process_tcp_flags_packet(self, datapath, pkt, actions, buffer_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        ip = pkt.get_protocol(ipv4.ipv4)
        protocol = ip.proto  # should be 6 - TCP code
        tcp_p = pkt.get_protocol(tcp.tcp)
        match1 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                 ipv4_src=ip.src,
                                 ipv4_dst=ip.dst,
                                 ip_proto=protocol,
                                 tcp_src=tcp_p.src_port,
                                 tcp_dst=tcp_p.dst_port)

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
                                0,
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
                    idle_timeout = self.CONF.UDP_IDLE_TIMEOUT
                elif protocol == in_proto.IPPROTO_TCP:
                    tcp_p = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip.src,
                                            ipv4_dst=ip.dst,
                                            ip_proto=protocol,
                                            tcp_src=tcp_p.src_port,
                                            tcp_dst=tcp_p.dst_port)
                    priority = TCP_UDP_PRIORITY_LEVEL
                    idle_timeout = self.CONF.TCP_IDLE_TIMEOUT
                elif protocol == in_proto.IPPROTO_UDP:
                    udp_p = pkt.get_protocol(udp.udp)

                    # TODO -> Debug
                    if udp_p.src_port == DNS_PORT or udp_p.dst_port == DNS_PORT:
                        print('DNS communication in table')

                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip.src,
                                            ipv4_dst=ip.dst,
                                            ip_proto=protocol,
                                            udp_src=udp_p.src_port,
                                            udp_dst=udp_p.dst_port)
                    priority = TCP_UDP_PRIORITY_LEVEL
                    idle_timeout = self.CONF.UDP_IDLE_TIMEOUT

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

        data = extract_match_from_packet(packet)

        if is_tcp_flags_packet(pkt, eth):
            self.save_tcp_flags_packet_info(msg, data)
            if not is_dns_communication(data):
                if msg.reason == ofproto_v1_5.OFPR_TABLE_MISS:
                    self.install_flow(datapath, msg, pkt, eth, out_port, actions)
                self.process_tcp_flags_packet(datapath, pkt, actions, msg.buffer_id)
        else:
            self.add_flow_to_stats_table(msg, data)
            if not is_dns_communication(data):
                self.install_flow(datapath, msg, pkt, eth, out_port, actions)

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
            self.controller_data_buffer.add_stats(data)

        except subprocess.CalledProcessError as err:
            self.logger.info("Error collecting data")
            self.logger.debug(err)

    def save_tcp_flags_packet_info(self, msg, data):
        # ipv6 not supported at the moment
        if data is not None:
            data['byte_count'] = msg.total_len
            data['packet_count'] = 1
            self.controller_data_buffer.add_tcp_flags_data(data)

    def add_flow_to_stats_table(self, msg, data):
        # ipv6 not supported at the moment, do not pass ICMP
        if data is not None:
            data['byte_count'] = msg.total_len
            data['packet_count'] = 1
            self.controller_data_buffer.add_new_flow_data(data)
