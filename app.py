from flask import Flask, request, redirect, render_template
import nmap
import re
import socket
import os

app = Flask(__name__)

def get_key(val):
    for key, value in my_dict.items():
         if val == value:
             return key


@app.route('/')
def form():
        return render_template("form.html")

@app.route('/result', methods= ["POST"])
def result():
    ip = request.form.get("ip")
    rng=request.form.get("range")
    ip_add_pattern = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(16|24))$")
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 1000
    ultimate={}
    Prts={}
    os={}
    if ip_add_pattern.search(ip):
        valid='valid'
    else:
        valid='Enter the Ip adress of your network with mask'
    port_range_valid=port_range_pattern.search(rng.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        nm = nmap.PortScanner()
        for port in range(port_min, port_max + 1):
            result = nm.scan(ip, str(port))
            ips=list(result['scan'])        
            for i in ips:
                port_status = (result['scan'][i]['tcp'][port]['state'])
                Prts[port]=port_status
                ultimate[i]=Prts
                se=nm.scan(i, arguments="-O",sudo=True)
                if i in se['scan']:
                    os[i]=se['scan'][i]['osmatch']
    print(ultimate)
    print(os)
    
    return render_template("result.html", ip=ip, rng=rng, valid=valid, output=ultimate,result=result,maxx=port_max,minn=port_min,os=os)
