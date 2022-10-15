# Previous byte and packet count doesn't include establish flow info - they are just here to speed up calculating
# data size in last interval

# Reseno azuriranje usled prvog i poslednjeg (kod tcp-a) paketa


class FlowData:
    # public data -> hash map with byte_count and packet_count
    def __init__(self, data, udp_padding):
        self.establish_flow_byte_count = data['byte_count']
        self.establish_flow_packet_count = data['packet_count']

        self.previous_byte_count = 0
        self.previous_packet_count = 0
        self.byte_count_list = []
        self.packet_count_list = []

        self.udp_padding = udp_padding
        self.tcp_flags_byte_count = 0
        self.tcp_flags_packet_count = 0
        self.tcp_flags_interval = 0

    # public - called from update
    def append_data(self, total_byte_count, total_packet_count):
        byte_count, packet_count = self.get_interval_values(total_byte_count, total_packet_count)

        if len(self.byte_count_list) == 0:
            byte_count = byte_count + self.establish_flow_byte_count
        self.byte_count_list.append(byte_count)

        if len(self.packet_count_list) == 0:
            packet_count = packet_count + self.establish_flow_packet_count
        self.packet_count_list.append(packet_count)

        self.previous_byte_count = total_byte_count
        self.previous_packet_count = total_packet_count

    # public - called from removed
    def add_final_data(self, total_byte_count, total_packet_count):
        byte_count, packet_count = self.get_interval_values(total_byte_count, total_packet_count)

        if len(self.byte_count_list) > 0:
            if self.tcp_flags_interval > 0:
                if self.tcp_flags_interval == len(self.byte_count_list):
                    self.byte_count_list.append(byte_count + self.tcp_flags_byte_count)
                else:
                    self.byte_count_list[-1] = self.byte_count_list[-1] + byte_count + self.tcp_flags_byte_count
        else:
            self.byte_count_list.append(self.establish_flow_byte_count + byte_count + self.tcp_flags_byte_count)

        if len(self.packet_count_list) > 0:
            if self.tcp_flags_interval > 0:
                if self.tcp_flags_interval == len(self.packet_count_list):
                    self.packet_count_list.append(packet_count + self.tcp_flags_packet_count)
                else:
                    self.packet_count_list[-1] = self.packet_count_list[-1] + packet_count + self.tcp_flags_packet_count
        else:
            self.packet_count_list.append(self.establish_flow_packet_count + packet_count + self.tcp_flags_packet_count)

    # public - called from tcp flags
    def add_tcp_flags_data(self, byte_count, packet_count):
        self.tcp_flags_byte_count = byte_count
        self.tcp_flags_packet_count = packet_count
        self.tcp_flags_interval = len(self.byte_count_list)

    # public - called from removed
    def remove_udp_padding(self):
        # there is no way to byte_count = 0 and packet_count <> 0, we can check only byte_count
        while self.byte_count_list[-1] == 0:
            del self.byte_count_list[-1:]
            del self.packet_count_list[-1:]

    def get_interval_values(self, total_byte_count, total_packet_count):
        byte_count = total_byte_count - self.previous_byte_count
        packet_count = total_packet_count - self.previous_packet_count
        return byte_count, packet_count
