from flow.v2.match import Match
from flow.v2.stats import FlowStats
from ryu.ryu.lib.packet import in_proto
import statistics
import scipy.stats

MIN_LENGTH = 2
DNS_PORT = 53

STATUS_ACTIVE = 1
STATUS_FINISHED = 2


class FlowInfo:
    def __init__(self, start_interval, entry, data, udp_idle_interval):
        self.start_interval = start_interval
        self.status = STATUS_ACTIVE
        self.match = Match(entry)
        self.stats = FlowStats(data)
        self.udp_idle_interval = udp_idle_interval

    # -----------------------------------------MATCH FUNCTIONS----------------------------------------------------------
    def compare_match_to_entry(self, match):
        return self.match.compare_match_to_entry(match)

    def compare_flows(self, other_flow):
        return self.match.compare_match(other_flow)

    def get_protocol_name(self):
        return self.match.get_protocol_name()

    def is_dns_communication(self):
        return self.match.is_dns_communication()

    # -----------------------------------------STATS FUNCTIONS----------------------------------------------------------