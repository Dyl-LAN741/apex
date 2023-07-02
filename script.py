# coding: utf-8

import base64
import jwt
import hashlib
import requests
import time
from datetime import datetime, timedelta
from config import api_url, api_id, api_key
import logging  # for debugging
from prometheus_client import start_http_server, REGISTRY
from prometheus_client.core import GaugeMetricFamily  # metrics prometheus
from time import sleep
from datetime import datetime, timedelta

# for debugging
logging.getLogger()
logging.basicConfig(
    level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s.%(funcName)s: %(message)s')

# constant of metrics
DATE_TIME = 0
ENDPOINT = 1
TARGET_IP = 2
USERNAME = 3
VERSION_OS = 4
MALWARE_NAME = 5
FPATH = 6
FNAME = 7
RNE = 8
METRICS_VALUES = 9

# logs recovery date
DAYS = 1
HOURS = 0
# logs history
previous_logs = []
# logs deleted in history
last_deletions = []
# first execution
is_first_query = True
# verify if history is empty
is_empty = True

# current time
now = datetime.today()
# last time
last_time = now - timedelta(days=DAYS, hours=HOURS) #7
# string of current time
now_str = now.strftime("%Y-%m-%d %H:%M:%S")
# string of last time
last_time_str = last_time.strftime("%Y-%m-%d %H:%M:%S")
# print(f"date_time: {last_time_str}")
# unix format
unix_timestamp = int(time.mktime(last_time.timetuple()))
# print(f"unix_tmstp: {unix_timestamp}")

# server info
use_url_base = api_url()
use_application_id = api_id()
use_api_key = api_key()
# This is the path for ProductAgents API
productAgentAPIPath = '/WebApp/api/v1/Logs/officescan_virus'
# currently Canonical-Request-Headers will always be empty
canonicalRequestHeaders = ''
# request specification
useQueryString = f'?output_format=CEF&page_token=0&since_time={unix_timestamp}'
useRequestBody = ''

class Collector(object):
    # Class role is to collect prometheus metrics on logs Forcepoint Firewall SMC

    def __init__(self):
        pass
    
    # chechsum for login to API Apex Central
    def __create_checksum__(self, http_method, raw_url, headers, request_body):
        string_to_hash = http_method.upper() + '|' + raw_url.lower() + '|' + headers + '|' + request_body
        base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
        return base64_string

    # json web token for connection to API Apex Central
    def __create_jwt_token__(self, appication_id, api_key, http_method, raw_url, headers, request_body,
                        iat=time.time(), algorithm='HS256', version='V1'):
        payload = {'appid': appication_id,
                'iat': iat,
                'version': version,
                'checksum': self.__create_checksum__(http_method, raw_url, headers, request_body)}
        token = jwt.encode(payload, api_key, algorithm=algorithm)
        return token

    # create and add metrics to prometheus
    def collect(self):
        global is_first_query, previous_logs, is_empty, last_time, last_deletions

        jwt_token = self.__create_jwt_token__(use_application_id, use_api_key, 'GET',
                             productAgentAPIPath + useQueryString,
                             canonicalRequestHeaders, useRequestBody, iat=time.time())

        headers = {'Authorization': 'Bearer ' + jwt_token,
                'Content-Type': 'application/json;charset=utf-8'}
        # Resquest to get logs
        request_result = requests.get(use_url_base + productAgentAPIPath +
                        useQueryString, headers=headers, verify=False)
        print(request_result.status_code)

        logs = request_result.json()["Data"]["Logs"]
        
        # metric definition for total event number
        metric_total_event = GaugeMetricFamily("apex_total_event", "Nombre total d'alertes'", labels=["nombre_event"])
        # metrics definition for logs details
        metric_priority_event = GaugeMetricFamily("apex_priority_event", "Détails des alertes",
                                                  labels=["date_time",
                                                          "endpoint",
                                                          "target_ip",
                                                          "username",
                                                          "version_os",
                                                          "malware",
                                                          "file_path",
                                                          "file_name",
                                                          "rne"])

        for elem in logs:  # read each logs
            # metrics tab of the log
            metrics_values = [''] * METRICS_VALUES
            # the log
            str_elem = str(elem)

            # parse log fields
            str_tab_elem_priority = str_elem.split("|")
            for index, elem_prio in enumerate(str_tab_elem_priority):
                str_tab_elem_priority[index] = elem_prio.replace("\\\\", "\\")
    
            malware_name = str_tab_elem_priority[5]
            log_detail = str_tab_elem_priority[7]
            log_detail = str_tab_elem_priority[7].split(" ")
            
            # log fields index 
            for index, detail in enumerate(log_detail):
                if "rt=" in detail:
                    date_time_index = index
                elif "duser=" in detail:
                    username_index = index
                elif "TMCMLogDetectedIP=" in detail:
                    target_ip_index = index
                elif "dhost=" in detail:
                    endpoint_index = index
                elif "deviceExternalId=" in detail:
                    event_id_index = index
                elif "dntdom=" in detail:
                    rne_index = index
                elif "TMCMdevicePlatform=" in detail:
                    os_version_index = index
                elif "deviceNtDomain=" in detail:
                    os_version_end_index = index
                elif "filePath" in detail:
                    file_path_index = index
                elif "fname=" in detail:
                    file_name_index = index
            # get each log fields
            datetime_str = log_detail[date_time_index].split("=")[1] + " " + log_detail[date_time_index+1]
            datetime_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
            datetime_object = datetime_object + timedelta(hours = 2)
            # log date verification
            if datetime_object < last_time:
                continue
            metrics_values[DATE_TIME] = datetime_object.strftime("%Y-%m-%d %H:%M:%S")
            metrics_values[USERNAME] = log_detail[username_index].split("=")[1]
            metrics_values[TARGET_IP] = log_detail[target_ip_index].split("=")[1]
            metrics_values[ENDPOINT] = log_detail[endpoint_index].split("=")[1]
            metrics_values[MALWARE_NAME] = malware_name
            metrics_values[RNE] = log_detail[rne_index].split("=")[1]
            metrics_values[VERSION_OS] = log_detail[os_version_index].split("=")[1]
            i = 1
            while i <= os_version_end_index - (os_version_index + 1):
                metrics_values[VERSION_OS] += " " + log_detail[os_version_index + i]
                i += 1
            metrics_values[FPATH] = log_detail[file_path_index].split("=")[1]
            metrics_values[FNAME] = log_detail[file_name_index].split("=")[1]
            i = 1
            while i <= file_path_index - (file_name_index + 1):
                metrics_values[FNAME] += " " + log_detail[file_name_index + i]
                i += 1
            event_id = log_detail[event_id_index].split("=")[1]
  
            new_metrics = False         # considering log will be not adding to prometheus
            in_previous_logs = False    # considering log is not in logs history 
            if is_first_query == True:      # if first execution
                if is_empty == True:        # if logs history is empty
                    previous_logs.append(metrics_values)    # add log in logs history
                    new_metrics = True      # can create metrics
                    is_empty = False        # logs history are not empty
                else:   # if logs history are not empty
                    for previous_log in previous_logs:      # log in logs history
                        index = 1           # we will compare all fields but not the date field
                        while index < len(metrics_values):
                            if metrics_values[index] in previous_log[index]:    # log fields is same as logs fields history
                                in_previous_logs = True     # log are already in history
                            else:
                                in_previous_logs = False    # log is not in history
                                break       # stop compare next fields
                            index = index + 1   # next field
                        if in_previous_logs == True:
                            break   # stop comparaison with history

                    if in_previous_logs == False:
                        previous_logs.append(metrics_values)    # add log in logs history
                        new_metrics = True

            elif is_first_query == False:   # not first execution
                in_deletions = False        # considering log are not deleted in logs history
                for previous_log in previous_logs:  # log in logs history
                    index = 1
                    while index < len(metrics_values):
                        if metrics_values[index] in previous_log[index]:    # log fields is same as logs fields history
                            in_previous_logs = True     # log are already in history
                        else:
                            in_previous_logs = False    # log is not in history
                            break       # stop compare next fields
                        index = index + 1
                    if in_previous_logs == True:
                        break   # stop comparaison with history
        
                for last_deletion in last_deletions:  # log deleted in logs deletions
                    index_del = 1
                    while index_del < len(last_deletion):
                        if metrics_values[index_del] in last_deletion[index_del]:   # log fields is same as logs fields deletions
                            in_deletions = True     # log are already in deletions
                        else:
                            in_deletions = False    # log is not in deletions
                            break   # stop comparaison with deletions
                        index_del = index_del + 1   # next log in deletions
                    
                    if in_deletions == True:
                        del last_deletions[last_deletions.index(last_deletion)]     # delete oldest log in deletions
                        last_deletions.append(metrics_values)   # add most recent log in deletions

                if in_previous_logs == False:
                    previous_logs.append(metrics_values)    # add log in logs history
                    if in_deletions == False:
                        new_metrics = True      # can create metrics

            if new_metrics == True:
                # adding new metrics in prometheus
                metric_priority_event.add_metric(
                    labels=[metrics_values[DATE_TIME],
                            metrics_values[ENDPOINT],
                            metrics_values[TARGET_IP],
                            metrics_values[USERNAME],
                            metrics_values[VERSION_OS],
                            metrics_values[MALWARE_NAME],
                            metrics_values[FPATH],
                            metrics_values[FNAME],
                            metrics_values[RNE]
                            ],
                    value=str(event_id))

        # only on not first function call
        if is_first_query == False:
            now = datetime.today()
            last_time = now - timedelta(days=DAYS, hours=HOURS)
            for log in previous_logs[:]:
                # covert log date to datetime type
                log_date = datetime.strptime(log[DATE_TIME], "%Y-%m-%d %H:%M:%S")
                # delete outdated logs in history
                if log_date < last_time:
                    last_deletions.append(previous_logs[previous_logs.index(log)])
                    del previous_logs[previous_logs.index(log)]
            last_time_deletions = now - timedelta(days=DAYS, hours=HOURS+1)
            for log in last_deletions[:]:
                # covert log date to datetime type
                log_date = datetime.strptime(log[DATE_TIME], "%Y-%m-%d %H:%M:%S")
                # delete outdated logs in deletions
                if log_date < last_time_deletions:
                    del last_deletions[last_deletions.index(log)]

        # add metric for number event
        metric_total_event.add_metric(labels=[f"{DAYS}j"], value=len(previous_logs))
        
        # # for debugging
        # for log in previous_logs: 
        #     print(log)
        # print("")
        # print(len(previous_logs))

        # after the first function call this boolean is set on False for the rest of the execution
        is_first_query = False

        # Collector() return all metrics
        yield metric_total_event
        yield metric_priority_event


if __name__ == "__main__":
    start_http_server(9400)  # http server on localhost and port :9400
    REGISTRY.register(Collector())
    while True:
        sleep(60)
