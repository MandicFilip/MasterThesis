import threading
import sys
import time
from data_collector import get_data
from DataTable import DataTable


def process_data(data):
    pass


def handler(sleep_interval, url):
    data = DataTable()

    while True:
        success = get_data(url, data)
        if success:
            process_data(data)
        else:
            data.fill_zeros()
        time.sleep(sleep_interval)


if len(sys.argv) < 3:
    exit(-1)

interval = int(sys.argv[1])
ryu_controller_url = sys.argv[2]

cThread = threading.Thread(target=handler, args=(interval, ryu_controller_url))
cThread.start()

# interval: 5
# url: http://localhost:8080/stats/flow/1

#
# # TODO slozenost
# for flow in body:
#     if flow.priority != TCP_UDP_PRIORITY_LEVEL:
#         new_flow = True
#         flow_match = self.ofpmatch_to_map(flow.match)
#
#         for entry in self.statistics_table['active_flows']:
#             if flow_match == entry['match']:
#                 new_flow = False
#                 entry['byte_count_array'].append(flow.byte_count - entry['total_byte_count'])
#                 entry['packet_count_array'].append(flow.packet_count - entry['total_packet_count'])
#                 entry['total_byte_count'] = flow.byte_count
#                 entry['total_packet_count'] = flow.packet_count
#                 entry['found_flag_metadata'] = True
#
#         if new_flow:
#             entry = self.create_flow_statistics_entry(flow_match, flow.byte_count, flow.packet_count)
#             self.statistics_table['active_flows'].append(entry)
#
# for entry in self.statistics_table['active_flows']:
#     if not entry['found_flag_metadata']:
#         self.statistics_table['finished_flows'].append(entry)
#         self.statistics_table['active_flows'].remove(entry)
#     else:
#         entry['found_flag_metadata'] = False
#
# def create_flow_statistics_entry(self, match, byte_count, packet_count):
#     entry = {'start_interval': self.interval_counter,
#              'match': match,
#              'total_byte_count': byte_count,
#              'total_packet_count': packet_count,
#              'byte_count_array': [],
#              'packet_count_array': [],
#              'found_flag_metadata': True}
#     entry['byte_count_array'].append(byte_count)
#     entry['packet_count_array'].append(packet_count)
#     return entry

#     def ofpmatch_to_map(self, match):
#         match_map = {'ip_proto': match['ip_proto'], 'ipv4_src': match['ipv4_src'], 'ipv4_dst': match['ipv4_dst']}
#
#         if match['ip_proto'] == in_proto.IPPROTO_TCP:
#             match_map['src_port'] = match['tcp_src']
#             match_map['dst_port'] = match['tcp_dst']
#         elif match['ip_proto'] == in_proto.IPPROTO_UDP:
#             match_map['src_port'] = match['udp_src']
#             match_map['dst_port'] = match['udp_dst']
#
#         return match_map
#
#     # for now just printing, later sending to program for processing
#     def forward_stats(self, stats):
#         data = {'stats': stats, 'interval': self.interval_counter}
#         # TODO dodati controller i proslediti request i response kako bih znao gde da posaljem, ne zaboraviti json konverziju
#
#     def preprocess_statistics(self, body):
#         stats = []
#         for flow in body:
#             if flow.priority != TCP_UDP_PRIORITY_LEVEL:
#                 match = self.ofpmatch_to_map(flow.match)
#                 stats.append({'match': match,
#                               'byte_count': flow.flow.byte_count,
#                               'packet_count': flow.packet_count})
#         return stats
#
#     @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
#     def _flow_stats_reply_handler(self, ev):
#         body = ev.msg.body
#
#         stats = self.preprocess_statistics(body)
#
#         self.interval_counter = self.interval_counter + 1
#         self.forward_stats(stats)