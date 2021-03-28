
import requests
import json


def get_data(url, data):
    x = requests.get(url)
    print(x.json())
    return False
