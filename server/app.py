import asyncio
import subprocess
import json
import requests
from requests.auth import HTTPDigestAuth
from pyasic.network import MinerNetwork
from pyasic import get_miner
from flask import Flask, request, jsonify
from flask_cors import CORS
from helpers.logger import logger

# XX: some weird situation where request.host_url
# shows up with http when tunneling from HTTP to HTTPS
def enforce_https_for_ngrok(url: str):
  if "ngrok" in url:
    if "http://" in url:
      return url.replace("http://", "https://")
  return url

def ping(host):
    try:
        if isinstance(host, list):
            return subprocess.check_output(['fping', '-a', '-q'] + host)
        else:
            return subprocess.check_output(['fping', '-a', '-q', host])
    except subprocess.CalledProcessError as e:
        # based on https://fping.org/fping.1.html
        # Exit status is 0 if all the hosts are reachable, 
        # 1 if some hosts were unreachable, 2 if any IP addresses were not found, 3 for invalid command line arguments, and 4 for a system call failure.
        if e.returncode == 1:
             return e.output

        raise RuntimeError('command "{}" return with error (code {}): {}'.format(e.cmd, e.returncode, e.output))

def get_pingable_hosts(host):
    return ping(host).splitlines()

def get_kernel_log_url(ip, with_auth=False):
     if not with_auth: 
          return f'http://{ip}/cgi-bin/get_kernel_log.cgi'
     else:
          return f'http://root:root@{ip}/cgi-bin/get_kernel_log.cgi'

def get_kernel_logs(ip, download=True):
     url = get_kernel_log_url(ip)
     auth = HTTPDigestAuth('root', 'root')
     return requests.get(url, auth=auth) if download else requests.head(url, auth=auth)

def has_kernel_logs(ip):
    try:
        resp = get_kernel_logs(ip, False)
        return resp.status_code == 200
    except:
         return False

def download_kernel_logs(ip):
     return get_kernel_logs(ip).text
     
async def get_miner_summary(miner):
    supported_commands = miner.api.get_commands()

    if "summary" in supported_commands:
       return await miner.api.send_command("summary")

    return None

# define asynchronous function to get miner and data
async def get_miner_data(miner_ip: str):
    # Use MinerFactory to get miner
    # MinerFactory is a singleton, so we can just get the instance in place
    miner = await get_miner(miner_ip)

    # Get data from the miner
    return await miner.get_data()

# define asynchronous function to scan for miners
async def scan_and_get_data(ip, mask=None):
    # Define network range to be used for scanning
    # This can take a list of IPs, a constructor string, or an IP and subnet mask
    # The standard mask is /24 (x.x.x.0-255), and you can pass any IP address in the subnet
    net = MinerNetwork(ip, mask=mask) if not isinstance(ip, list) else MinerNetwork(ip)

    logger.info(f"running network scan for {ip}")

    # Scan the network for miners
    # This function returns a list of miners of the correct type as a class
    miners: list = await net.scan_network_for_miners()

    logger.info(f"got miners: {miners}")

    # We can now get data from any of these miners
    # To do them all we have to create a list of tasks and gather them
    tasks = [miner.get_data() for miner in miners]

    logger.info(f"gonna get data for individual miners")

    # Gather all tasks asynchronously and run them
    results = await asyncio.gather(*tasks)

    logger.info(f"got results: {results}")

    logger.info(f"going to pull summaries for individual miners")

    summary_tasks = [get_miner_summary(miner) for miner in miners]
    summary_results = await asyncio.gather(*summary_tasks)

    logger.info(f"got summary data for miners {summary_results}")

    # return a list of dicts, without datetime (not json serializable)
    def to_clean_dict(l):
        r = l.asdict()
        r.pop('datetime')
        return r

    result_output = list(map(to_clean_dict, results))

    logger.info(f"merging miner data with miner summary")

    for i, _ in enumerate(result_output):
        result_output[i]["summary"] = summary_results[i]

    return result_output

async def configure_miner_pool(miner_ip, group_name, url, username, password):
    net = MinerNetwork([miner_ip])
    miners: list = await net.scan_network_for_miners()

    if len(miners) == 0:
        return

    miner = miners[0]

    config = await miner.get_config()
    config_dict = config.as_dict()
    config_dict["pool_groups"] = [
        {
            'quota': 1,
            'group_name': group_name,
            'pools': [
                {
                    'url': url,
                    'username': username,
                    'password': password
                },
                {
                    'url': '',
                    'username': '',
                    'password': ''
                },
                {
                    'url': '',
                    'username': '',
                    'password': ''
                }
            ]
        }
    ]
    config.from_dict(config_dict)
    await miner.send_config(config)


app = Flask(__name__)
CORS(app)

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
    ips = request.args.get('ips').split(",")

    logger.info(f"got scan request for {ips}")

    pingable_ips = get_pingable_hosts(ips)

    logger.info(f"identified pingable IPs: {pingable_ips}")
    logger.info(f"gonna run scan on IPs: {ips}")

    miners = await scan_and_get_data(ips)

    logger.info(f"got {len(miners)} via scan")
    logger.info(f"going to look at potential miners")

    # identify IPs that are pingable but are NOT identified as working miners
    potential_miners = list(filter(lambda ip: has_kernel_logs(ip), list(set(pingable_ips) - set(map(lambda m: m['ip'], miners)))))

    logger.info(f"identified potential miners {potential_miners}")

    results = {}

    clean_host_url = enforce_https_for_ngrok(request.host_url)

    for miner in miners:
         results[miner['ip']] = { 'miner_data': miner, 'kernel_log': f'{clean_host_url}kernel-logs?ip={miner["ip"]}' }

    for potential_miner in potential_miners:
         results[potential_miner] = { 'kernel_log': f'{clean_host_url}kernel-logs?ip={potential_miner}' }

    return app.response_class(
        response=json.dumps(results),
        status=200,
        mimetype='application/json'
    )

@app.route('/ping', methods=['GET'])
async def run_ping():
    ips = request.args.get('ips').split(",")

    pingable_ips = get_pingable_hosts(ips)

    results = {}

    for ip in pingable_ips:
         results[ip.decode('utf-8')] = ""

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
    ip = request.args.get('ip')
    logger.info(f"will try downloading kernel logs for {ip}")
    return download_kernel_logs(ip)

@app.route('/flask-health-check')
def flask_health_check():
    return 'success'

@app.route('/set-pool-config', methods=['POST'])
async def set_pool_config():
    content = request.json
    logger.info(f"setting pool config {content}")
    await configure_miner_pool(content['miner_ip'], content['group_name'], content['url'], content['username'], content['password'])
    return jsonify({ 'result': 'ok' })
