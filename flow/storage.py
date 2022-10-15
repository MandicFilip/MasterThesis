import os
from datetime import datetime


def stringify_statistics(flow):
    stats = ""
    stats = stats + str(flow.byte_mean) + " "
    stats = stats + str(flow.byte_median) + " "
    stats = stats + str(flow.byte_mode) + " "
    stats = stats + str(flow.byte_standard_deviation) + " "
    stats = stats + str(flow.byte_fisher_skew) + " "
    stats = stats + str(flow.byte_fisher_kurtosis) + " "
    stats = stats + str(flow.byte_correlation) + "\n"

    stats = stats + str(flow.packet_mean) + " "
    stats = stats + str(flow.packet_median) + " "
    stats = stats + str(flow.packet_mode) + " "
    stats = stats + str(flow.packet_standard_deviation) + " "
    stats = stats + str(flow.packet_fisher_skew) + " "
    stats = stats + str(flow.packet_fisher_kurtosis) + " "
    stats = stats + str(flow.packet_correlation) + "\n"
    return stats


def format_flow_info(flow):
    flow_string = ""
    flow_string = flow_string + str(flow.match.ip_src) + " "
    flow_string = flow_string + str(flow.match.ip_dst) + " "
    flow_string = flow_string + str(flow.match.port_src) + " "
    flow_string = flow_string + str(flow.match.port_dst) + " "
    flow_string = flow_string + str(flow.match.protocol_code) + "\n"

    # flow_string = flow_string + str(flow.total_byte_count) + " "
    # flow_string = flow_string + str(flow.total_packet_count) + "\n"

    flow_string = flow_string + str(flow.data.byte_count_list) + "\n"
    flow_string = flow_string + str(flow.data.packet_count_list) + "\n"

    # flow_string = flow_string + stringify_statistics(flow) + "\n"
    return flow_string


def init_file(file, time, collect_interval, save_interval):
    if os.path.exists(file):
        os.remove(file)
    try:
        file = open(file, "w+")
        file.write('Start time: ' + time + "\n")
        file.write('Collect Interval: ' + str(collect_interval) + '\n')
        file.write('Save Interval: ' + str(save_interval) + '\n\n')
        file.close()
    except IOError:
        print("Error opening file: " + file)


def init_finished_flows_storage(collect_interval, save_interval, finished_flows_file):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    if os.path.exists(finished_flows_file):
        os.remove(finished_flows_file)
    try:
        file = open(finished_flows_file, "w+")
        file.write('Start time: ' + current_time + "\n")
        file.write('Collect Interval: ' + str(collect_interval) + '\n')
        file.write('Save Interval: ' + str(save_interval) + '\n\n')
        file.close()
    except IOError:
        print("Error opening file: " + finished_flows_file)


def save_active_flows(file, flows):
    if os.path.exists(file):
        os.remove(file)
    try:
        file = open(file, "w+")
        for flow in flows:
            flow_string = format_flow_info(flow)
            file.write(flow_string)
            file.write("\n")

        file.close()
    except IOError:
        print("Error opening file: " + file)


def save_finished_flows(file, flows):
    if not os.path.exists(file):
        print("File does not exist!")
        return False
    try:
        file = open(file, "a")
        for flow in flows:
            flow_string = format_flow_info(flow)
            file.write(flow_string)
            file.write("\n")

        file.close()
        return True
    except IOError:
        print("Error saving finished flows")
        return False
