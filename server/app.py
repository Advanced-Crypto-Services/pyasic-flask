import asyncio
import subprocess
import json
import requests
from requests.auth import HTTPDigestAuth
from pyasic.network import MinerNetwork
from pyasic import get_miner
from flask import Flask, request, jsonify
from flask_cors import CORS

def ping(host):
    try:
        return subprocess.check_output(['fping', '-a', '-q', '-g', host])
    except subprocess.CalledProcessError as e:
        # based on https://fping.org/fping.1.html
        # Exit status is 0 if all the hosts are reachable, 
        # 1 if some hosts were unreachable, 2 if any IP addresses were not found, 3 for invalid command line arguments, and 4 for a system call failure.
        if e.returncode == 1:
             return e.output

        raise RuntimeError('command "{}" return with error (code {}): {}'.format(e.cmd, e.returncode, e.output))

def get_pingable_hosts(host):
     # return ping(host).split(' ')
     return ['10.33.13.90', '10.33.13.100', '10.33.13.114', '10.33.13.115', '10.33.13.116', '10.33.13.119', '10.33.13.120', '10.33.13.122', '10.33.13.123', '10.33.13.125', '10.33.13.126', '10.33.13.127', '10.33.13.128', '10.33.13.132', '10.33.13.134', '10.33.13.135', '10.33.13.136']

def get_kernel_log_url(ip, with_auth=False):
     if not with_auth: 
          return f'http://{ip}/cgi-bin/get_kernel_log.cgi'
     else:
          return f'http://root:root@{ip}/cgi-bin/get_kernel_log.cgi'

def get_kernel_logs(ip):
     return requests.get(get_kernel_log_url(ip), auth=HTTPDigestAuth('root', 'root'))

def has_kernel_logs(ip):
    try:
        resp = get_kernel_logs(ip)
        return resp.status_code == 200
    except:
         return False

def download_kernel_logs(ip):
     return get_kernel_logs(ip).text
     

# define asynchronous function to get miner and data
async def get_miner_data(miner_ip: str):
    # Use MinerFactory to get miner
    # MinerFactory is a singleton, so we can just get the instance in place
    miner = await get_miner(miner_ip)

    # Get data from the miner
    return await miner.get_data()

# define asynchronous function to scan for miners
async def scan_and_get_data(ip, mask):
    # Define network range to be used for scanning
    # This can take a list of IPs, a constructor string, or an IP and subnet mask
    # The standard mask is /24 (x.x.x.0-255), and you can pass any IP address in the subnet
    net = MinerNetwork(ip, mask=mask)

    hosts = list(map(lambda ip: str(ip), list(net.hosts())) )

    # Scan the network for miners
    # This function returns a list of miners of the correct type as a class
    miners: list = await net.scan_network_for_miners()

    # We can now get data from any of these miners
    # To do them all we have to create a list of tasks and gather them
    tasks = [miner.get_data() for miner in miners]
    # Gather all tasks asynchronously and run them
    results = await asyncio.gather(*tasks)

    # return a list of dicts, without datetime (not json serializable)
    def to_clean_dict(l):
        r = l.asdict()
        r.pop('datetime')
        return r

    return list(map(to_clean_dict, results))

app = Flask(__name__)
CORS(app)
cors = CORS(app, resources={r'/miner': {'origins': '*'}, r'/scan': {'origins': '*'}})

@app.route('/miner', methods=['GET'])
async def miner():
    data = await get_miner_data(request.args.get('ip'))
    response = app.response_class(
        response=data.as_json(),
        status=200,
        mimetype='application/json'
    )
    return response


@app.route('/scan', methods=['GET'])
async def scan():
    ip = request.args.get('ip')
    mask = request.args.get('mask', default=24, type=int)

    miners = await scan_and_get_data(ip, mask)
    pingable_ips = get_pingable_hosts(f'{ip}/{mask}')

    # identify IPs that are pingable but are NOT identified as working miners
    potential_miners = list(filter(lambda ip: has_kernel_logs(ip), list(set(pingable_ips) - set(map(lambda m: m['ip'], miners)))))

    results = {}

    for miner in miners:
         results[miner['ip']] = { 'miner_data': miner, 'kernel_log': f'{request.host_url}kernel-logs?ip={miner["ip"]}' }

    for potential_miner in potential_miners:
         results[potential_miner] = { 'kernel_log': f'{request.host_url}kernel-logs?ip={potential_miner}' }

    response = app.response_class(
        response=json.dumps(results),
        status=200,
        mimetype='application/json'
    )
    return response

@app.route('/info')
def info():
	return jsonify({
		'connecting_ip': request.headers['X-Real-IP'],
		'proxy_ip': request.headers['X-Forwarded-For'],
		'host': request.headers['Host'],
		'user-agent': request.headers['User-Agent']
	})

@app.route('/kernel-logs', methods=['GET'])
def kernel_logs():
	return download_kernel_logs(request.args.get('ip'))

@app.route('/flask-health-check')
def flask_health_check():
	return 'success'