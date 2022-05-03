from operator import itemgetter

import tests.table_update_test.test_update_test_data
import random
from dataryu import FlowDataTable


def run_test(dataTable, data, result):
    random.shuffle(data)
    data.sort(key=itemgetter('ip_src', 'ip_dst', 'port_src', 'port_dst'))
    dataTable.update_data(data)

    success = True
    values = []
    for i in range(0, len(result)):
        if dataTable.active_flows[i].protocol_code != result[i]:
            success = False
        values.append(dataTable.active_flows[i].protocol_code)
    pass

    if success:
        print("Test passed!")
    else:
        print("Test failed!")
        print("Expected values: " + str(result))
        print("Real values: " + str(values))


def run_delete_test(dataTable, values, result):
    for value in values:
        dataTable.finish_flow(value)

    success = True
    values = []
    for i in range(0, len(result)):
        if dataTable.finished_flows[i].protocol_code != result[i]:
            success = False
        values.append(dataTable.finished_flows[i].protocol_code)
    pass

    if success:
        print("Test passed!")
    else:
        print("Test failed!")
        print("Expected values: " + str(result))
        print("Real values: " + str(values))
    pass


table = FlowDataTable.FlowDataTable()

run_test(table, tests.table_update_test.test_update_test_data.init_data_table, tests.table_update_test.test_update_test_data.init_result)
run_test(table, tests.table_update_test.test_update_test_data.first_update, tests.table_update_test.test_update_test_data.first_update_result)
run_delete_test(table, tests.table_update_test.test_update_test_data.first_finished, tests.table_update_test.test_update_test_data.first_finished_results)
run_test(table, tests.table_update_test.test_update_test_data.second_update, tests.table_update_test.test_update_test_data.second_update_result)
run_delete_test(table, tests.table_update_test.test_update_test_data.second_finished, tests.table_update_test.test_update_test_data.second_finished_results)
run_test(table, tests.table_update_test.test_update_test_data.third_update, tests.table_update_test.test_update_test_data.third_update_result)
