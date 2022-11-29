class DummyTable:
    def __init__(self):
        self.active_flows = []
        self.finished_flows = []

    def initialize(self, tcp_idle_interval, udp_idle_interval):
        return

    def on_add_flow(self, info):
        return

    def on_update(self, data):
        return 0, 0

    def on_tcp_flags_package(self, tcp_flow_data):
        return

    def on_save_flows(self, active_flows_file, finished_flows_file):
        return

    def calc_stats(self):
        return

    def get_interval(self):
        return 0

    def on_insert_values(self, update_flows):
        return

    def update_flow_status():
        return
