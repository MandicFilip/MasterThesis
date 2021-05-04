import os
from datetime import datetime

file_name = "finished_flows.info"


def init_storage(interval_length):
    if os.path.exists(file_name):
        os.remove(file_name)

    try:
        file = open(file_name, "w+")

        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        file.write(current_time + "\n")

        file.write("Interval length: " + str(interval_length) + "\n\n")

        file.close()
    except IOError:
        print("Error opening file!")
    pass


def format_flow_info(flow):
    flow_string = ""
    flow_string = flow_string + flow.ip_src + " "
    flow_string = flow_string + flow.ip_dst + " "
    flow_string = flow_string + flow.port_src + " "
    flow_string = flow_string + flow.port_dst + " "
    flow_string = flow_string + flow.protocol_code + " "

    flow_string = flow_string + "\n"

    flow_string = flow_string + flow.total_byte_count + " " + flow.total_packet_count + "\n"

    flow_string = flow_string + flow_string(flow.byte_count_list) + "\n"
    flow_string = flow_string + flow_string(flow.packet_count_list) + "\n"

    # TODO save stats when calculated

    return flow_string


def save_to_file(finished_flows, file):
    for flow in finished_flows:
        flow_string = format_flow_info(flow)
        file.write(flow_string)
        file.write("\n")


def save_flows(finished_flows):

    if not os.path.exists(file_name):
        print("Error with file")
        return False
    try:
        file = open(file_name, "a")
        save_to_file(finished_flows, file)
        file.close()
        return True
    except IOError:
        print("Error saving finished flows")
        return False
