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

TABLE_MISS_PRIORITY_LEVEL = 0
ICMP_PRIORITY_LEVEL = 1
TCP_UDP_PRIORITY_LEVEL = 2
TCP_FLAGS_PRIORITY_LEVEL = 3


class SwitchController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.CONF = cfg.CONF
        self.CONF.register_opts([cfg.IntOpt('IDLE_TIMEOUT', default=10, help='Idle Timeout'),
                                 cfg.IntOpt('DELETE_INTERVAL', default=1, help='Delete Interval')])
        self.logger.info("Idle timeout: %d seconds", self.CONF.IDLE_TIMEOUT)
        self.logger.info("Delete Interval: %d seconds", self.CONF.DELETE_INTERVAL)

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
        self.add_flow(datapath, TABLE_MISS_PRIORITY_LEVEL, match, actions)

        # install tcp flags flow entry - we need packet with flags for tcp session end to remove flow from table
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=(0x001 | 0x004))
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, TCP_FLAGS_PRIORITY_LEVEL, match, actions)

    @staticmethod
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

    def ethernet_processing(self, datapath, msg, eth):
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

        match2 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                 ipv4_src=ip.dst,
                                 ipv4_dst=ip.src,
                                 tcp_src=tcp_p.dst_port,
                                 tcp_dst=tcp_p.src_port,
                                 ip_proto=protocol)

        if buffer_id == ofproto.OFP_NO_BUFFER:
            buffer_id = None

        # Give some time for peers to finish communication and then remove flow from table
        hub.spawn(self.delete_tcp_flow_pair, datapath, match1, match2, actions, buffer_id)

    def delete_tcp_flow_pair(self, datapath, match1, match2, actions, buffer_id=None):
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

        mod = parser.OFPFlowMod(datapath,
                                cookie,
                                cookie_mask,
                                table_id,
                                ofproto.OFPFC_DELETE,
                                idle_timeout,
                                hard_timeout,
                                priority,
                                buffer_id,
                                ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                ofproto.OFPFF_SEND_FLOW_REM,
                                importance,
                                match2,
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
                    self.add_flow(datapath, priority, match, actions, idle_timeout, msg.buffer_id)
                else:
                    self.add_flow(datapath, priority, match, actions, idle_timeout)

    @staticmethod
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

        in_port, out_port = self.ethernet_processing(datapath, msg, eth)

        actions = [parser.OFPActionOutput(out_port)]

        if self.is_tcp_flags_packet(pkt, eth):
            self.process_tcp_flags_packet(datapath, pkt, actions, msg.buffer_id)
        else:
            self.install_flow(datapath, msg, pkt, eth, out_port, actions)

        self.forward_packet(datapath, msg, in_port, actions)
