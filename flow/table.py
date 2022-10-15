from flow.flow import FlowInfo
from flow.storage import save_active_flows, save_finished_flows
from ryu.ryu.lib.packet import in_proto


def get_dict_match(data):
    return {
        'ip_src': data['ip_src'],
        'ip_dst': data['ip_dst'],
        'port_src': data['port_src'],
        'port_dst': data['port_dst'],
        'protocol_code': data['protocol_code']
    }


class FlowDataTable:
    def __init__(self, udp_interval):
        self.active_flows = []
        self.finished_flows = []
        self.interval = 0
        self.udp_interval = udp_interval

    def on_add_flow(self, info):
        new_entry = FlowInfo(start_interval=self.interval, data=info, udp_idle_interval=self.udp_interval)
        if new_entry.is_dns_communication():
            self.finished_flows.append(new_entry)
            new_entry.recalculate_stats() # check here if additional method is needed
        else:
            i = 0
            while i < len(self.active_flows) and self.active_flows[i].compare_flows(new_entry) == -1:
                i = i + 1
            self.active_flows.insert(i, new_entry)

    def on_update(self, data):
        self.update_active_flows_table(data)
        self.calc_stats()
        self.separate_finished_flows()

    def update_active_flows_table(self, sorted_data):
        i = 0
        j = 0
        while i < len(sorted_data) and (j < len(self.active_flows)):
            value = self.active_flows[j].compare_match_to_entry(sorted_data[i])

            if value < 0:
                # There is a flow that we are unaware of
                print('Error - there is a flow for which we do not have data in table')
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

    def calc_stats(self):
        for flow in self.active_flows:
            if not flow.is_pair_flow_set() and flow.is_active():
                pair = self.find_pair_for_flow(flow)
                if pair is not None:
                    flow.set_pair_flow(pair)
            flow.recalculate_stats()
            flow.calc_correlation()

        print("Stats done")

    def separate_finished_flows(self):
        i = 0
        while i < len(self.active_flows):
            if self.active_flows[i].finished:
                flow = self.active_flows[i]
                pair = self.find_pair_for_flow(self.active_flows[i])
                if pair is not None:
                    if pair.finished:
                        flow.perform_final_processing(self.udp_interval)
                        pair.perform_final_processing(self.udp_interval)
                        flow.recalculate_stats()
                        pair.recalculate_stats()
                        self.finished_flows.append(flow)
                        self.finished_flows.append(pair)
                        self.active_flows.pop(i)
                        self.active_flows.remove(pair)
                    else:
                        self.active_flows[i].add_back_padding()
                else:
                    flow.perform_final_processing(self.udp_interval)
                    self.finished_flows.append(flow)
                    self.active_flows.pop(i)
            else:
                i = i + 1

    def on_flow_removed(self, finished_flow_data):
        index = self.find_flow(finished_flow_data)

        if index != -1:
            flow = self.active_flows[index]
            flow.update_counters(finished_flow_data['byte_count'], finished_flow_data['packet_count'])
            flow.finish()
        else:
            print('Can not find finished flow\n' + str(finished_flow_data))

    def clear_finished_flows(self):
        self.finished_flows = []

    def save_flows(self, active_flows_file, finished_flows_file):
        save_active_flows(active_flows_file, self.active_flows)
        save_finished_flows(finished_flows_file, self.finished_flows)
        self.clear_finished_flows()
        print('Saved flows')

    def find_flow(self, key):
        low = 0
        high = len(self.active_flows) - 1
        while low <= high:
            mid = int((low + high) / 2)
            flow = self.active_flows[mid]
            value = flow.compare_match_to_entry(key)
            if value == 0:
                return mid
            if value < 0:
                high = mid - 1
            else:
                low = mid + 1
        return -1

    def find_pair_for_flow(self, flow):
        key = {'ip_src': flow.ip_dst, 'ip_dst': flow.ip_src, 'port_src': flow.port_dst, 'port_dst': flow.port_src,
               'protocol_code': flow.protocol_code}
        index = self.find_flow(key)
        if index != -1:
            return self.active_flows[index]
        return None