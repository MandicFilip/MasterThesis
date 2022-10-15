import shlex
import subprocess
from operator import itemgetter

from ryu.ryu.lib.packet import in_proto

TCP_UDP_PRIORITY_LEVEL = 2


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


GET_STATISTICS_COMMAND = 'sudo ovs-ofctl -O openflow15 dump-flows s1'


def get_statistics():
    args = shlex.split(GET_STATISTICS_COMMAND)
    output = subprocess.check_output(args, stderr=subprocess.STDOUT)

    return process_flow_data(output)
