from operator import itemgetter

import tests.test_collection
import random
import DataTable


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


table = DataTable.DataTable()

run_test(table, tests.test_collection.init_data_table, tests.test_collection.init_result)
run_test(table, tests.test_collection.first_update, tests.test_collection.first_update_result)
run_delete_test(table, tests.test_collection.first_finished, tests.test_collection.first_finished_results)
run_test(table, tests.test_collection.second_update, tests.test_collection.second_update_result)
run_delete_test(table, tests.test_collection.second_finished, tests.test_collection.second_finished_results)
run_test(table, tests.test_collection.third_update, tests.test_collection.third_update_result)
