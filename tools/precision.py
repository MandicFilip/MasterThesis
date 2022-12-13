from operator import itemgetter


WIRESHARK_DATA_FILE_STRESS = '..\\wireshark_data\\stress_test.txt'
FINISHED_FLOWS_FILE_STRESS = '..\\output\\stress\\finished_flows.info'

WIRESHARK_DATA_FILE_CUSTOM = '..\\wireshark_data\\custom_test.txt'
FINISHED_FLOWS_FILE_CUSTOM = '..\\output\\custom\\finished_flows.info'


OUTPUT_FILE = 'output_stress.txt'

ERROR_FINISHED_FLOWS = -1


def read_csv(filename):
    file = open(filename, 'r')
    lines = file.readlines()
    flows = []
    for row in lines:
        parts = row.split(',')
        for i in range(0, len(parts)):
            if parts[i][-1] == '\n':
                parts[i] = parts[i][:-1]
            if parts[i][-1] == '\"':
                parts[i] = parts[i][:-1]
            if parts[i][0] == '\"':
                parts[i] = parts[i][1:]

        flow = {}
        flow['ip_src'] = parts[0]
        flow['port_src'] = int(parts[1])
        flow['ip_dst'] = parts[2]
        flow['port_dst'] = int(parts[3])
        flow['packet_count'] = int(parts[6])
        flow['byte_count'] = int(parts[7])

        other_flow = {}
        other_flow['ip_src'] = parts[2]
        other_flow['port_src'] = int(parts[3])
        other_flow['ip_dst'] = parts[0]
        other_flow['port_dst'] = int(parts[1])
        other_flow['packet_count'] = int(parts[8])
        other_flow['byte_count'] = int(parts[9])

        flows.append(flow)
        flows.append(other_flow)

    file.close()
    flows.sort(key=itemgetter('ip_src', 'ip_dst', 'port_src', 'port_dst'))

    return flows


def read_finished_flows(filename):
    file = open(filename, 'r')
    lines = file.readlines()
    flows = []

    if len(lines) < 4:
        exit(ERROR_FINISHED_FLOWS)

    #skip header and empty line
    i = 4
    while i < len(lines):
        first_line = lines[i]
        second_line = lines[i + 1]
        i = i + 5

        parts = first_line.split()

        flow = {}
        flow['ip_src'] = parts[0]
        flow['ip_dst'] = parts[1]
        flow['port_src'] = int(parts[2])
        flow['port_dst'] = int(parts[3])

        parts = second_line.split()

        flow['byte_count'] = int(parts[1])
        flow['packet_count'] = int(parts[2])

        flows.append(flow)

    file.close()
    flows.sort(key=itemgetter('ip_src', 'ip_dst', 'port_src', 'port_dst'))

    return flows


def is_same_match(flow1, flow2):
    return flow1['ip_src'] == flow2['ip_src'] and flow1['ip_dst'] == flow2['ip_dst'] and flow1['port_src'] == flow2['port_src'] and flow1['port_dst'] == flow2['port_dst']


def merge_inputs(flow1, flow2):
    flow1['byte_count'] = flow1['byte_count'] + flow2['byte_count']
    flow1['packet_count'] = flow1['packet_count'] + flow2['packet_count']
    return flow1


def process_flows(flows):
    # merge same flows
    i = 0
    while i < len(flows):
        j = i + 1
        while j < len(flows) and is_same_match(flows[i], flows[j]):
            flows[i] = merge_inputs(flows[i], flows[j])
            flows.pop(j)
        i = i + 1

    # remove empty flows
    i = 0
    while i < len(flows):
        if flows[i]['byte_count'] == 0 or flows[i]['packet_count'] == 0:
            flows.pop(i)
        else:
            i = i + 1

    return flows


def compare_match(flow1, flow2):
    if flow1['ip_src'] < flow2['ip_src']:
        return -1
    if flow1['ip_src'] > flow2['ip_src']:
        return 1

    if flow1['ip_dst'] < flow2['ip_dst']:
        return -1
    if flow1['ip_dst'] > flow2['ip_dst']:
        return 1

    if flow1['port_src'] < flow2['port_src']:
        return -1
    if flow1['port_src'] > flow2['port_src']:
        return 1

    if flow1['port_dst'] < flow2['port_dst']:
        return -1
    if flow1['port_dst'] > flow2['port_dst']:
        return 1

    return 0


def init_output(filename):
    file = open(filename, 'w')
    return file


def close_output(file):
    file.close()


def record_not_paired_flow(output, flow, side):
    line = f'0   Unknown flow in {side}: {str(flow)}\n'
    output.write(line)


def record_not_matched_values(output, flow_w, flow_t):
    line = f"1   BAD   Flows not matched: "
    line = line + f"({flow_w['ip_src']}, {flow_w['ip_dst']}, {flow_w['port_src']}, {flow_w['port_dst']}) --->     "
    line = line + f"({flow_w['byte_count']}, {flow_w['packet_count']})   !=   "
    line = line + f"({flow_t['byte_count']}, {flow_t['packet_count']})\n"
    output.write(line)


def record_matched_values(output, flow_w):
    line = f"2   GOOD   Flows matched: "
    line = line + f"({flow_w['ip_src']}, {flow_w['ip_dst']}, {flow_w['port_src']}, {flow_w['port_dst']}) --->     "
    line = line + f"({flow_w['byte_count']}, {flow_w['packet_count']})\n"
    output.write(line)


def compare_counters(flow_w, flow_t):
    return flow_w['byte_count'] == flow_t['byte_count'] and flow_w['packet_count'] == flow_t['packet_count']


def compare(wireshark_flows, traffic_monitor_flows, output):
    unpaired = 0
    not_matched = 0
    matched = 0

    i = 0
    j = 0
    while (i < len(wireshark_flows)) and (j < len(traffic_monitor_flows)):
        value = compare_match(wireshark_flows[i], traffic_monitor_flows[j])

        if value < 0:
            record_not_paired_flow(output, wireshark_flows[i], 'wireshark flows')
            unpaired = unpaired + 1
            i = i + 1
        elif value > 0:
            record_not_paired_flow(output, traffic_monitor_flows[j], 'traffic monitor flows')
            unpaired = unpaired + 1
            j = j + 1
        else:
            if compare_counters(wireshark_flows[i], traffic_monitor_flows[j]):
                record_matched_values(output, wireshark_flows[i])
                matched = matched + 1
            else:
                record_not_matched_values(output, wireshark_flows[i], traffic_monitor_flows[j])
                not_matched = not_matched + 1
            i = i + 1
            j = j + 1

    while i < len(wireshark_flows):
        record_not_paired_flow(output, wireshark_flows[i], 'wireshark flows')
        unpaired = unpaired + 1
        i = i + 1

    while j < len(traffic_monitor_flows):
        record_not_paired_flow(output, traffic_monitor_flows[j], 'traffic monitor flows')
        unpaired = unpaired + 1
        j = j + 1

    print(f'Not paired: {str(unpaired)}')
    print(f'Not matched: {str(not_matched)}')
    print(f'GOOD: {str(matched)}')


def main():
    wireshark_flows = read_csv(WIRESHARK_DATA_FILE_STRESS)
    wireshark_flows = process_flows(wireshark_flows)
    print('Wireshark: ' + str(len(wireshark_flows)))

    traffic_monitor_flows = read_finished_flows(FINISHED_FLOWS_FILE_STRESS)
    traffic_monitor_flows = process_flows(traffic_monitor_flows)
    print('Traffic monitor: ' + str(len(traffic_monitor_flows)))

    output_file = init_output(OUTPUT_FILE)
    compare(wireshark_flows, traffic_monitor_flows, output_file)
    close_output(output_file)

main()
