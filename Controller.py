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
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub
from ryu import cfg

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.prev_stats = None
        self.stats_switch = None
        self.stat_thread = hub.spawn(self._request_stats_thread)
        self.CONF = cfg.CONF
        self.CONF.register_opts([cfg.IntOpt('INTERVAL', default=10, help=('Monitoring Interval'))])
        self.logger.info("Statistics interval value: %d seconds", self.CONF.INTERVAL)


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
        self.add_flow(datapath, 0, match, actions)

    def _request_stats_thread(self):
        while True:
            if self.stats_switch is not None:
                datapath = self.stats_switch
                self.logger.debug('send stats request: %016x', datapath.id)
                parser = datapath.ofproto_parser

                req = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)

            hub.sleep(self.CONF.INTERVAL)

    def ofpmatch_to_map(self, match):
        match_map = {'ip_proto': match['ip_proto'], 'ipv4_src': match['ipv4_src'], 'ipv4_dst': match['ipv4_dst']}

        if match['ip_proto'] == in_proto.IPPROTO_TCP:
            match_map['tcp_src'] = match['tcp_src']
            match_map['tcp_dst'] = match['tcp_dst']
        elif match['ip_proto'] == in_proto.IPPROTO_UDP:
            match_map['udp_src'] = match['udp_src']
            match_map['udp_dst'] = match['udp_dst']

        return match_map

    # for now just printing, later sending to program for processing
    def forward_stats(self, diff_stats):
        print("Here are diff stats (Match, bytes counter, packet counter):")
        print(diff_stats['active'])

        print("here are finished flows:")
        print(diff_stats['finished'])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # filter stats
        flow_stat = {'active': None, 'finished': None}
        active_flows = []
        finished_flows = []

        # filter data and packet in flow
        for flow in body:
            if flow.priority > 0:
                active_flows.append({'match': self.ofpmatch_to_map(flow.match),
                                     'byte_count': flow.byte_count,
                                     'packet_count': flow.packet_count,
                                     'total_byte_count': flow.byte_count,
                                     'total_packet_count': flow.packet_count})

        # if not first report, find diff
        if self.prev_stats is not None:
            # complexity!!!
            for new_stat in active_flows:
                for old_stat in self.prev_stats['active']:
                    if new_stat['match'] == old_stat['match']:
                        old_stat['found'] = True
                        new_stat['byte_count'] = new_stat['byte_count'] - old_stat['total_byte_count']
                        new_stat['packet_count'] = new_stat['packet_count'] - old_stat['total_packet_count']
                        break

            for old_stat in self.prev_stats['active']:
                if old_stat.get('found') is None:
                    finished_flows.append(old_stat['match'])

        flow_stat['active'] = active_flows
        flow_stat['finished'] = finished_flows
        self.prev_stats = flow_stat

        self.forward_stats(flow_stat)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check if it is IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                protocol = ip.proto

                match = parser.OFPMatch()

                # Match if not TCP or UDP (for example ICMP protocol)
                if (protocol != in_proto.IPPROTO_TCP) and (protocol != in_proto.IPPROTO_UDP):
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip.src, ipv4_dst=ip.dst,
                                            ip_proto=protocol)

                elif protocol == in_proto.IPPROTO_TCP:
                    tcp_p = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip.src,
                                            ipv4_dst=ip.dst,
                                            tcp_src=tcp_p.src_port,
                                            tcp_dst=tcp_p.dst_port,
                                            ip_proto=protocol)

                elif protocol == in_proto.IPPROTO_UDP:
                    udp_p = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip.src,
                                            ipv4_dst=ip.dst,
                                            udp_src=udp_p.src_port,
                                            udp_dst=udp_p.dst_port,
                                            ip_proto=protocol)

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
