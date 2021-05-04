
init_data_table = [
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 10345,
        'port_dst': 20356,
        'protocol_code': 1,
        'byte_count': 20,
        'packet_count': 3
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 11300,
        'port_dst': 21300,
        'protocol_code': 2,
        'byte_count': 250,
        'packet_count': 32
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 17000,
        'port_dst': 27000,
        'protocol_code': 3,
        'byte_count': 2500,
        'packet_count': 37
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 19345,
        'port_dst': 29356,
        'protocol_code': 4,
        'byte_count': 202020,
        'packet_count': 3333
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14000,
        'port_dst': 24000,
        'protocol_code': 5,
        'byte_count': 320,
        'packet_count': 33
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14050,
        'port_dst': 25050,
        'protocol_code': 6,
        'byte_count': 3454,
        'packet_count': 202
    },
    {
        'ip_src': "100.15.14.33",
        'ip_dst': "102.13.11.2",
        'port_src': 10200,
        'port_dst': 20200,
        'protocol_code': 7,
        'byte_count': 400,
        'packet_count': 2
    },
    {
        'ip_src': "110.0.0.1",
        'ip_dst': "120.0.0.2",
        'port_src': 19045,
        'port_dst': 29056,
        'protocol_code': 8,
        'byte_count': 25300,
        'packet_count': 3222
    },
    {
        'ip_src': "127.0.0.1",
        'ip_dst': "127.0.0.16",
        'port_src': 10000,
        'port_dst': 20000,
        'protocol_code': 9,
        'byte_count': 120,
        'packet_count': 31
    },
    {
        'ip_src': "200.0.0.1",
        'ip_dst': "230.13.14.2",
        'port_src': 11545,
        'port_dst': 21556,
        'protocol_code': 10,
        'byte_count': 20200,
        'packet_count': 3000
    },
]

init_result = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

first_update = [
    {
        'ip_src': "1.0.0.1",
        'ip_dst': "12.13.14.2",
        'port_src': 15555,
        'port_dst': 22556,
        'protocol_code': 0,
        'byte_count': 300,
        'packet_count': 3
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 10345,
        'port_dst': 20356,
        'protocol_code': 1,
        'byte_count': 320,
        'packet_count': 33
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 11300,
        'port_dst': 21300,
        'protocol_code': 2,
        'byte_count': 550,
        'packet_count': 35
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 17000,
        'port_dst': 27000,
        'protocol_code': 3,
        'byte_count': 2800,
        'packet_count': 40
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 19345,
        'port_dst': 29356,
        'protocol_code': 4,
        'byte_count': 202320,
        'packet_count': 3336
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14000,
        'port_dst': 24000,
        'protocol_code': 5,
        'byte_count': 620,
        'packet_count': 36
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14050,
        'port_dst': 25050,
        'protocol_code': 6,
        'byte_count': 3754,
        'packet_count': 205
    },
    {
        'ip_src': "100.15.14.33",
        'ip_dst': "10.13.11.2",
        'port_src': 10500,
        'port_dst': 20500,
        'protocol_code': 13,
        'byte_count': 300,
        'packet_count': 3
    },
    {
        'ip_src': "100.15.14.33",
        'ip_dst': "102.13.11.2",
        'port_src': 10200,
        'port_dst': 20200,
        'protocol_code': 7,
        'byte_count': 700,
        'packet_count': 5
    },
    {
        'ip_src': "110.0.0.1",
        'ip_dst': "120.0.0.2",
        'port_src': 19045,
        'port_dst': 29056,
        'protocol_code': 8,
        'byte_count': 25600,
        'packet_count': 3225
    },
    {
        'ip_src': "127.0.0.1",
        'ip_dst': "127.0.0.16",
        'port_src': 10000,
        'port_dst': 20000,
        'protocol_code': 9,
        'byte_count': 420,
        'packet_count': 34
    },
    {
        'ip_src': "200.0.0.1",
        'ip_dst': "230.13.14.2",
        'port_src': 11545,
        'port_dst': 21556,
        'protocol_code': 10,
        'byte_count': 20500,
        'packet_count': 3003
    },
    {
        'ip_src': "202.0.0.1",
        'ip_dst': "230.13.14.2",
        'port_src': 15545,
        'port_dst': 25556,
        'protocol_code': 11,
        'byte_count': 300,
        'packet_count': 3
    },
    {
        'ip_src': "202.0.0.1",
        'ip_dst': "232.13.14.2",
        'port_src': 15555,
        'port_dst': 22556,
        'protocol_code': 12,
        'byte_count': 300,
        'packet_count': 3
    }
]

first_update_result = [0, 1, 2, 3, 4, 5, 6, 13, 7, 8, 9, 10, 11, 12]

first_finished = [
    {
        'ip_src': "1.0.0.1",
        'ip_dst': "12.13.14.2",
        'port_src': 15555,
        'port_dst': 22556,
        'protocol_code': 0,
        'byte_count': 300,
        'packet_count': 3
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 17000,
        'port_dst': 27000,
        'protocol_code': 3,
        'byte_count': 2800,
        'packet_count': 40
    },
    {
        'ip_src': "100.15.14.33",
        'ip_dst': "10.13.11.2",
        'port_src': 10500,
        'port_dst': 20500,
        'protocol_code': 13,
        'byte_count': 300,
        'packet_count': 3
    },
    {
        'ip_src': "202.0.0.1",
        'ip_dst': "230.13.14.2",
        'port_src': 15545,
        'port_dst': 25556,
        'protocol_code': 11,
        'byte_count': 300,
        'packet_count': 3
    },
    {
        'ip_src': "202.0.0.1",
        'ip_dst': "232.13.14.2",
        'port_src': 15555,
        'port_dst': 22556,
        'protocol_code': 12,
        'byte_count': 300,
        'packet_count': 3
    }
]

first_finished_results = [0, 3, 13, 11, 12]

second_update = [
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 10345,
        'port_dst': 20356,
        'protocol_code': 1,
        'byte_count': 360,
        'packet_count': 37
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 11300,
        'port_dst': 21300,
        'protocol_code': 2,
        'byte_count': 590,
        'packet_count': 39
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 19345,
        'port_dst': 29356,
        'protocol_code': 4,
        'byte_count': 202360,
        'packet_count': 3340
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14000,
        'port_dst': 24000,
        'protocol_code': 5,
        'byte_count': 660,
        'packet_count': 40
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14050,
        'port_dst': 25050,
        'protocol_code': 6,
        'byte_count': 3794,
        'packet_count': 209
    },
    {
        'ip_src': "100.15.14.33",
        'ip_dst': "102.13.11.2",
        'port_src': 10200,
        'port_dst': 20200,
        'protocol_code': 7,
        'byte_count': 740,
        'packet_count': 9
    },
    {
        'ip_src': "110.0.0.1",
        'ip_dst': "120.0.0.2",
        'port_src': 19045,
        'port_dst': 29056,
        'protocol_code': 8,
        'byte_count': 25640,
        'packet_count': 3229
    },
    {
        'ip_src': "127.0.0.1",
        'ip_dst': "127.0.0.16",
        'port_src': 10000,
        'port_dst': 20000,
        'protocol_code': 9,
        'byte_count': 460,
        'packet_count': 38
    },
    {
        'ip_src': "200.0.0.1",
        'ip_dst': "230.13.14.2",
        'port_src': 11545,
        'port_dst': 21556,
        'protocol_code': 10,
        'byte_count': 20540,
        'packet_count': 3007
    },
]

second_update_result = [1, 2, 4, 5, 6, 7, 8, 9, 10]

second_finished = [
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 19345,
        'port_dst': 29356,
        'protocol_code': 4,
        'byte_count': 202360,
        'packet_count': 3340
    },
    {
        'ip_src': "200.0.0.1",
        'ip_dst': "230.13.14.2",
        'port_src': 11545,
        'port_dst': 21556,
        'protocol_code': 10,
        'byte_count': 20540,
        'packet_count': 3007
    },
{
        'ip_src': "205.0.0.1",
        'ip_dst': "245.13.14.2",
        'port_src': 12000,
        'port_dst': 22000,
        'protocol_code': 16,
        'byte_count': 500,
        'packet_count': 5
    },
    {
        'ip_src': "206.0.0.1",
        'ip_dst': "236.13.14.2",
        'port_src': 11200,
        'port_dst': 21200,
        'protocol_code': 17,
        'byte_count': 600,
        'packet_count': 6
    },
]

second_finished_results = [0, 3, 13, 11, 12, 4, 10, 16, 17]

third_update = [
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 10345,
        'port_dst': 20356,
        'protocol_code': 1,
        'byte_count': 5360,
        'packet_count': 87
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.2",
        'port_src': 11300,
        'port_dst': 21300,
        'protocol_code': 2,
        'byte_count': 5590,
        'packet_count': 89
    },
    {
        'ip_src': "10.0.0.1",
        'ip_dst': "10.0.0.96",
        'port_src': 19000,
        'port_dst': 29000,
        'protocol_code': 14,
        'byte_count': 5000,
        'packet_count': 50
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14000,
        'port_dst': 24000,
        'protocol_code': 5,
        'byte_count': 5660,
        'packet_count': 90
    },
    {
        'ip_src': "10.0.0.2",
        'ip_dst': "10.0.0.1",
        'port_src': 14050,
        'port_dst': 25050,
        'protocol_code': 6,
        'byte_count': 8794,
        'packet_count': 259
    },
    {
        'ip_src': "100.15.14.33",
        'ip_dst': "102.13.11.2",
        'port_src': 10200,
        'port_dst': 20200,
        'protocol_code': 7,
        'byte_count': 5740,
        'packet_count': 59
    },
    {
        'ip_src': "110.0.0.1",
        'ip_dst': "120.0.0.2",
        'port_src': 19045,
        'port_dst': 29056,
        'protocol_code': 8,
        'byte_count': 30640,
        'packet_count': 3279
    },
    {
        'ip_src': "127.0.0.1",
        'ip_dst': "127.0.0.16",
        'port_src': 10000,
        'port_dst': 20000,
        'protocol_code': 9,
        'byte_count': 5460,
        'packet_count': 88
    },
    {
        'ip_src': "205.0.0.1",
        'ip_dst': "235.13.14.2",
        'port_src': 11000,
        'port_dst': 21000,
        'protocol_code': 15,
        'byte_count': 5000,
        'packet_count': 50
    },
]

third_update_result = [1, 2, 14, 5, 6, 7, 8, 9, 15]
