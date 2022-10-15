from v2.storageV2 import save_active_flows, save_finished_flows
from v2.flowV2 import FlowInfoV2


def find_flow(flows_list, key):
    low = 0
    high = len(flows_list) - 1
    while low <= high:
        mid = int((low + high) / 2)
        flow = flows_list[mid]
        value = flow.compare_match_to_entry(key)
        if value == 0:
            return mid
        if value < 0:
            high = mid - 1
        else:
            low = mid + 1
    return -1


class FlowDataTableV2:
    def __init__(self, udp_interval):
        self.active_flows = []
        self.finished_flows = []
        self.interval = 0
        self.udp_interval = udp_interval
        self.dns_flows = []

    # public
    def on_add_flow(self, info):
        new_entry = FlowInfoV2(start_interval=self.interval, data=info, udp_idle_interval=self.udp_interval)
        if new_entry.is_dns_communication():
            self.dns_flows.append(new_entry)
            new_entry.process_dns()
        else:
            self.insert_to_active_flows(new_entry)

    def insert_to_active_flows(self, entry):
        i = 0
        while i < len(self.active_flows) and self.active_flows[i].compare_flows(entry) == -1:
            i = i + 1
        self.active_flows.insert(i, entry)

    # public
    def on_update(self, data):
        self.update_active_flows_table(data)
        self.update_flow_status()

    def update_active_flows_table(self, sorted_data):
        i = 0
        j = 0
        while i < len(sorted_data) and (j < len(self.active_flows)):
            value = self.active_flows[j].compare_match_to_entry(sorted_data[i])

            if value < 0:
                # There is a flow that we are unaware of - could be that the first package in .pcap is tcp finish
                i = i + 1
                j = j + 1
            elif value > 0:
                # finished flow, no input for it
                j = j + 1
            else:
                self.active_flows[j].update_counters(sorted_data[i]['byte_count'], sorted_data[i]['packet_count'])
                i = i + 1
                j = j + 1

        self.interval = self.interval + 1

    def update_flow_status(self):
        i = 0
        while i < len(self.active_flows):
            flow = self.active_flows[i]
            if flow.is_active():
                if not flow.has_pair():
                    pair = self.find_pair_for_flow(flow)
                    if pair is not None:
                        if not pair.has_pair():
                            flow.set_pair(pair)
                            pair.set_pair(flow)
            i = i + 1

        i = 0
        while i < len(self.finished_flows):
            flow = self.finished_flows[i]
            pair = flow.get_pair()
            if pair is not None:
                if pair.is_waiting() or pair.is_finished():
                    flow.set_finished()
                    pair.set_finished()
            i = i + 1

    # public
    def on_flow_removed(self, finished_flow_data):
        index = self.find_active_flow(finished_flow_data)
        if index != -1:
            flow = self.active_flows[index]
            flow.on_flow_removed(finished_flow_data['byte_count'], finished_flow_data['packet_count'])
            self.finished_flows.append(flow)
            self.active_flows.pop(index)
        else:
            print('Can not find finished flow\n' + str(finished_flow_data))

    # public
    def on_tcp_flags_package(self, tcp_flow_data):
        index = self.find_active_flow(tcp_flow_data)
        if index != -1:
            flow = self.active_flows[index]
            flow.add_last_tcp_package_data(tcp_flow_data['byte_count'], tcp_flow_data['packet_count'])

    def clear_finished_flows(self):
        # remove all flows marked as finished
        i = 0
        while i < len(self.finished_flows):
            flow = self.finished_flows[i]
            if flow.is_finished():
                self.finished_flows.pop(i)
            else:
                i = i + 1

    # public
    def on_save_flows(self, active_flows_file, finished_flows_file):
        #self.calc_stats()
        save_active_flows(active_flows_file, self.active_flows)
        save_finished_flows(finished_flows_file, self.finished_flows)
        save_finished_flows(finished_flows_file, self.dns_flows)

    def find_active_flow(self, key):
        return find_flow(self.active_flows, key)

    def find_finish_flow(self, key):
        return find_flow(self.finished_flows, key)

    def find_pair_for_flow(self, flow):
        key = flow.create_opposite_entry
        index = self.find_active_flow(key)
        if index != -1:
            return self.active_flows[index]

        index = self.find_finish_flow(key)
        if index != -1:
            return self.finished_flows[index]
        return None

    #def calc_stats(self):
    #    i = 0
    #    while i < len(self.finished_flows):
    #        self.finished_flows[i].calc_stats()
    #        i = i + 1
