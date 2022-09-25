from ryu.ryu.lib.packet import in_proto

DNS_PORT = 53


class Match:
    def __init__(self, entry):
        self.ip_src = entry['ip_src']
        self.ip_dst = entry['ip_dst']
        self.port_src = entry['port_src']
        self.port_dst = entry['port_dst']
        self.protocol_code = entry['protocol_code']

    def compare_match_to_entry(self, entry):
        if self.ip_src != entry['ip_src']:
            if self.ip_src < entry['ip_src']:
                return 1
            else:
                return -1

        if self.ip_dst != entry['ip_dst']:
            if self.ip_dst < entry['ip_dst']:
                return 1
            else:
                return -1

        if self.port_src != entry['port_src']:
            if self.port_src < entry['port_src']:
                return 1
            else:
                return -1

        if self.port_dst != entry['port_dst']:
            if self.port_dst < entry['port_dst']:
                return 1
            else:
                return -1

        return 0

    def compare_match(self, match):
        entry = {'ip_src': match.ip_src, 'ip_dst': match.ip_dst,
                 'port_src': match.port_src, 'port_dst': match.port_dst}
        return self.compare_match_to_entry(entry)

    def create_opposite_match(self):
        entry = {'ip_src': self.ip_dst, 'ip_dst': self.ip_src,
                 'port_src': self.port_dst, 'port_dst': self.port_src, 'protocol_code': self.protocol_code}
        return Match(entry)

    def get_protocol_name(self):
        if self.protocol_code == in_proto.IPPROTO_TCP:
            return 'TCP'
        elif self.protocol_code == in_proto.IPPROTO_UDP:
            return 'UDP'
        return 'Not Supported'

    def is_dns_communication(self):
        return self.protocol_code == in_proto.IPPROTO_UDP and (self.port_src == DNS_PORT or self.port_dst == DNS_PORT)