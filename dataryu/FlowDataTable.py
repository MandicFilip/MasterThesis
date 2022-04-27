from dataryu.FlowInfo import FlowInfo


def get_dict_match(data):
    return {
        'ip_src': data['ip_src'],
        'ip_dst': data['ip_dst'],
        'port_src': data['port_src'],
        'port_dst': data['port_dst'],
        'protocol_code': data['protocol_code']
    }


class FlowDataTable:
    def __init__(self):
        self.active_flows = []
        self.finished_flows = []
        self.interval = 0

    def fill_zeros(self):
        for flow in self.active_flows:
            print(flow)
            flow.update_counters(0, 0)
        self.interval = self.interval + 1

    def update_data(self, sorted_data):
        i = 0
        j = 0
        while i < len(sorted_data) and (j < len(self.active_flows)):
            value = self.active_flows[j].compare_match_to_entry(sorted_data[i])

            if value < 0:
                # new flow should be added
                new_entry = FlowInfo(start_interval=self.interval, data=sorted_data[i])
                self.active_flows.insert(j, new_entry)
                i = i + 1
                j = j + 1
            elif value > 0:
                j = j + 1
            else:
                self.active_flows[j].update_counters(sorted_data[i]['byte_count'], sorted_data[i]['packet_count'])
                i = i + 1
                j = j + 1

        while i < len(sorted_data):
            new_entry = FlowInfo(start_interval=self.interval, data=sorted_data[i])
            self.active_flows.append(new_entry)
            i = i + 1

        self.interval = self.interval + 1

    def find_active_flow(self, key):
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

    def finish_flow(self, finished_flow_data):
        index = self.find_active_flow(finished_flow_data)

        if index == -1:
            # flow not in table
            entry = FlowInfo(self.interval, finished_flow_data)
            self.finished_flows.append(entry)
        else:
            flow = self.active_flows.pop(index)
            flow.update_counters(finished_flow_data['byte_count'], finished_flow_data['packet_count'])
            self.finished_flows.append(flow)

    def clear_finished_flows(self):
        self.finished_flows.clear()
        pass

    # copy to FullStatsApp
    def calc_stats(self):
        pass
