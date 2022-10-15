from flow.v2.flow_dataV2 import FlowData
from flow.v2.match import Match

MIN_LENGTH = 2
DNS_PORT = 53

STATUS_ACTIVE = 1
STATUS_WAITING = 2
STATUS_FINISHED = 3


class FlowInfoV2:
    def __init__(self, start_interval, entry, data, udp_idle_interval):
        self.start_interval = start_interval
        self.status = STATUS_ACTIVE
        self.match = Match(entry)
        self.data = FlowData(data, udp_idle_interval)
        self.udp_idle_interval = udp_idle_interval
        self.pair = None

    # -----------------------------------------MATCH FUNCTIONS----------------------------------------------------------
    def compare_match_to_entry(self, match):
        return self.match.compare_match_to_entry(match)

    def compare_flows(self, other_flow):
        return self.match.compare_match(other_flow)

    def get_protocol_name(self):
        return self.match.get_protocol_name()

    def is_dns_communication(self):
        return self.match.is_dns_communication()

    def set_finished(self):
        self.status = STATUS_FINISHED

    def is_active(self):
        return self.status == STATUS_ACTIVE

    def is_waiting(self):
        return self.status == STATUS_WAITING

    def is_finished(self):
        return self.status == STATUS_FINISHED

    def has_pair(self):
        return self.pair is not None

    def set_pair(self, pair):
        self.pair = pair

    def get_pair(self):
        return self.pair

    def create_opposite_entry(self):
        return self.match.create_opposite_entry()

    # -----------------------------------------COUNTERS FUNCTIONS-------------------------------------------------------

    def update_counters(self, total_byte_count, total_packet_count):
        if self.status == STATUS_ACTIVE:
            self.data.append_data(total_byte_count, total_packet_count)

    def add_last_tcp_package_data(self, byte_count, packet_count):
        self.data.add_tcp_flags_data(byte_count, packet_count)

    def on_flow_removed(self, total_byte_count, total_packet_count):
        if self.pair is None:
            self.status = STATUS_FINISHED
        else:
            self.status = STATUS_WAITING

        self.data.add_final_data(total_byte_count, total_packet_count)
        if self.match.is_udp():
            self.data.remove_udp_padding()

    def process_dns(self):
        self.data.append_data(0, 0)
        self.status = STATUS_FINISHED
