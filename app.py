from flask import Flask, request
import pickle
import logging
import pandas as pd
import numpy as np
import re
import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
import logging

logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s', datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG)

app = Flask(__name__)
classes_data = None
load_model = None

lineformat = re.compile(r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST) )(?P<url>.+)(http\/1\.1")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["])""", re.IGNORECASE)

load_model = pickle.load(open('threat_model.pkl', 'rb'))

with open('classes.json', 'rb') as fp:
    classes_data = pickle.load(fp)

def check_classes(method=None, url=None):
    method_index = 0
    url_index = 0
    try:
        if method and method in classes_data["method"]:
            method_index = np.where(classes_data["method"] == method)
            method_index = method_index[0]
            logging.info(method_index)
        if url and url in classes_data["path"]:
            url_index = np.where(classes_data["path"] == url)
            url_index = url_index[0]
        if method_index and url_index:
            return method_index, url_index
    except Exception as e:
        logging.info(e)
        return 0, 0


def block_redirect_traffic(ip, start_time, end_time):
    if ip and start_time and end_time:
        cmd = "bash block_ip.sh "+ ip +" "+ start_time + " " + end_time
        logging.info("Blocking IP --> %s From %s to %s", ip, start_time, end_time)
        logging.info(cmd)
        os.system(cmd)
        return "blocked_ip"
    else:
        return "Not blocked"


def predict_threat(method=0, protocol=0, path=0, headers=0, query=0, body=0):
    try:
        data = {'method':[method], 'protocol':[protocol], 'path':[path], 'headers':[headers], 'query':[query], 'body':[body]}
        df = pd.DataFrame(data)
        p = load_model.predict(df)
        return p
    except Exception as e:
        logging.info(e)
        return None



def parse_data(data):
    try:
        data = re.search(lineformat, data)
        if data:
            datadict = data.groupdict()
            ip = datadict["ipaddress"]
            datetimestring = datadict["dateandtime"]
            url = datadict["url"]
            bytessent = datadict["bytessent"]
            referrer = datadict["refferer"]
            useragent = datadict["useragent"]
            status = datadict["statuscode"]
            method = data.group(6)
            return datadict, ip, datetimestring, url, bytessent, referrer, useragent, status, method
    except Exception as e:
        logging.info(e)

def get_classification(data):
    try:
        datadict, ip, datetimestring, url, bytessent, referrer, useragent, status, method = parse_data(data)
        method, url = check_classes(method, url)
        if method != "None" and url != "None":
            p = predict_threat(method=method, protocol=0, path=url, headers=0, query=0, body=0)
            if p[0] == 0:
                current_time = datetime.now()
                add_5 = current_time + relativedelta(minutes=5)
                start_time = current_time.strftime("%H:%M:%S")
                end_time = add_5.strftime("%H:%M:%S")

                block_redirect_traffic(ip, start_time, end_time)
        return "classified"
    except Exception as e:
        logging.info(e)


def get_classification(data):
    try:
        datadict, ip, datetimestring, url, bytessent, referrer, useragent, status, method = parse_data(data)
        method, url = check_classes(method, url)
        if method != "None" and url != "None":
            p = predict_threat(method=method, protocol=0, path=url, headers=0, query=0, body=0)
            if p[0] == 0:
                current_time = datetime.now()
                add_5 = current_time + relativedelta(minutes=5)
                start_time = current_time.strftime("%H:%M:%S")
                end_time = add_5.strftime("%H:%M:%S")

                block_redirect_traffic(ip, start_time, end_time)
        return "classified"
    except Exception as e:
        logging.info(e)
        return "Not Classified"


@app.route('/classify', methods = ['GET', 'POST'])
def get_log_classification():
    try:
        data = request.form["data"]
        logging.info(data)
       # logging.info(predict_threat())
        if data:
            return get_classification(data)
        else:
            logging.info("No data")
            return "No data"
    except Exception as e:
        logging.info(e)
        return "Error"

if __name__ == '__main__':
    app.run()

