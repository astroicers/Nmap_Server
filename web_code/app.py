# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from pymongo import MongoClient
import re
import subprocess


def fuzzer_search(fuzzer_input):
    fuzzer_ip_list = ['product', 'ip', 'extrainfo',
                      'port',  'name', 'cpe', 'version', 'time_man']
    out_list = []
    for fuzzer_data in fuzzer_ip_list:
        rexExp = re.compile('.*' + fuzzer_input + '.*', re.IGNORECASE)
        res = mon.toybox.ip_list.find({fuzzer_data: rexExp})

        for rs in res:
            if rs not in out_list:
                out_list.append(rs)

    fuzzer_nse_list = ['vuln.ms17-010.hack']

    for fuzzer_data in fuzzer_nse_list:
        rexExp = re.compile('.*' + fuzzer_input + '.*', re.IGNORECASE)
        res = mon.toybox.nse_list.find({fuzzer_data: rexExp})

        for rs in res:
            if rs not in out_list:
                out_list.append(rs)

    return out_list


app = Flask(__name__)
mon = MongoClient('mongodb://' + 'root' + ':' + 'example' + '@127.0.0.1')


@app.route("/add_task", methods=['GET', 'POST'])
def scan():
    command = [
        'python2.7', '/config/muti_nmap_mongo.py']

    if request.method == 'POST':
        search_host = request.form.get('search_host')
        search_port = request.form.get('search_port')
        search_threads = request.form.get('search_threads')

        scan_mode_list = request.form.get('scan_mode_list')
        ping_list = request.form.get('ping_list')
        speed_list = request.form.get('speed_list')
        other_listf = request.form.get('other_list-f')
        other_list6 = request.form.get('other_list-6')
    command.append('-i')
    command.append(search_host)
    command.append('-p')
    command.append(search_port)
    command.append('-t')
    command.append(search_threads)
    command.append('-a')
    temp2 = [scan_mode_list, ping_list, speed_list, other_listf, other_list6]
    temp = ''
    for x in temp2:
        if x != None:
            temp += x+' '
    command.append(temp)
    process = subprocess.Popen(command, stderr=subprocess.PIPE)
    return render_template('add_scan.html', command=command)


@app.route("/nmap", methods=['GET', 'POST'])
def nmap_gui():
    scan_mode_list = [
        {
            'id': '1',
            'arg': '-sT',
            'name': 'TCP Connect Scan',
            'text': u'利用TCP協定，建立完整的3向交握連線後在進行掃描，雖然準確率比較高，但易留下紀錄。'
        },
    ]
    ping_list = [
        {
            'id': '1',
            'arg': '-P0',
            'name': 'Don\'t Ping',
            'text': u'執行掃描前，不目標主機。'
        }
    ]
    speed_list = [
        {
            'id': '1',
            'arg': '-T0',
            'name': 'Paranoid',
            'text': u'每五秒鐘發送一個封包。'
        }
    ]
    other_list = [
        {
            'id': '1',
            'arg': '-f',
            'name': 'Fragmentation',
            'text': u'發送碎片封包，資料長度為8byte，增加封包過濾器、防火牆與IDS的檢查難度。'
        },
        {
            'id': '2',
            'arg': '-6',
            'name': 'IPv6',
            'text': u'支援掃描IPv6。'
        }
    ]
    return render_template('nmap_gui.html', scan_mode_list=scan_mode_list, ping_list=ping_list, speed_list=speed_list, other_list=other_list)


@app.route("/", methods=['GET', 'POST'])
def index():
    scan_list = {}
    target_list = []
    nse_list = {}
    search_filter = ''
    if request.method == 'POST':
        search_filter = request.form['search_filter']
    # ip form
    for x in fuzzer_search(search_filter):
        try:
            if x['ip'] not in target_list:
                target_list.append(x['ip'])
                scan_list.update({x['ip']: {}})
                nse_list.update({x['ip']: {}})
        except KeyError:
            if x['_id'] not in target_list:
                target_list.append(x['_id'])
                scan_list.update({x['_id']: {}})
                nse_list.update({x['_id']: {}})

    # port form
    for x in target_list:
        for y in mon.toybox.ip_list.find({'ip': x}):
            scan_list[x].update(
                {y['port']: y, 'time_man': y['time_man'], 'time_pc': y['time_pc']})

    # nse form
    for x in target_list:
        for y in mon.toybox.nse_list.find({'_id': x}):
            nse_list[x].update(y)

    return render_template('index.html', nse_list=nse_list, target_list=target_list, scan_list=scan_list, search_filter=search_filter)


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5200, debug=True)
