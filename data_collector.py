import requests
import json
from operator import itemgetter

TCP_UDP_PRIORITY_LEVEL = 2
TCP_PROTOCOL_CODE = 6
UDP_PROTOCOL_CODE = 17


def format_match(match):
    return {'ip_src': match['nw_src'],
            'ip_dst': match['nw_dst'],
            'port_src': match['tp_src'],
            'port_dst': match['tp_dst'],
            'protocol_code': match['nw_proto']}


def unpack_data(raw_data):
    data_array = []
    for flow in raw_data:
        if flow['priority'] == TCP_UDP_PRIORITY_LEVEL:
            flow_dict = format_match(flow['match'])
            flow_dict['byte_count'] = flow['byte_count']
            flow_dict['packet_count'] = flow['packet_count']
            data_array.append(flow_dict)

    data_array.sort(key=itemgetter('ip_src', 'ip_dst', 'port_src', 'port_dst', 'protocol_code'))

    return data_array


def get_data(url, dataTable):
    try:
        response = requests.get(url)
        response.raise_for_status()

        print("received data")
        new_data = unpack_data(response.json()['1'])
        dataTable.update_data(new_data)
        return True
    except requests.exceptions.HTTPError as err:
        print("Bad response received! Exception: " + err)
        return False
