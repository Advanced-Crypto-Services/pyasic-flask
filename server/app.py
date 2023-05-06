import asyncio
import functools
from pyasic import get_miner
from flask import Flask, request, jsonify


# define asynchronous function to get miner and data
async def get_miner_data(miner_ip: str):
    # Use MinerFactory to get miner
    # MinerFactory is a singleton, so we can just get the instance in place
    miner = await get_miner(miner_ip)

    # Get data from the miner
    return await miner.get_data()

from pyasic.network import MinerNetwork


# define asynchronous function to scan for miners
async def scan_and_get_data(ips):
    # Define network range to be used for scanning
    # This can take a list of IPs, a constructor string, or an IP and subnet mask
    # The standard mask is /24 (x.x.x.0-255), and you can pass any IP address in the subnet
    net = MinerNetwork(ips)
    # Scan the network for miners
    # This function returns a list of miners of the correct type as a class
    miners: list = await net.scan_network_for_miners()

    # We can now get data from any of these miners
    # To do them all we have to create a list of tasks and gather them
    tasks = [miner.get_data() for miner in miners]
    # Gather all tasks asynchronously and run them
    return await asyncio.gather(*tasks)

app = Flask(__name__)

@app.route('/miner', methods=['GET'])
async def miner():
	data = await get_miner_data(request.args.get("ip"))
	return data.as_json()

@app.route('/scan', methods=['GET'])
async def scan():
	miners = await scan_and_get_data(request.args.get("ips").split(","))
	
	result = "["

	for miner in miners:
		result += f'{miner.as_json()},'

		return f'{result.strip(",")} ]' 

@app.route('/info')
def info():
	return jsonify({
		'connecting_ip': request.headers['X-Real-IP'],
		'proxy_ip': request.headers['X-Forwarded-For'],
		'host': request.headers['Host'],
		'user-agent': request.headers['User-Agent']
	})

@app.route('/flask-health-check')
def flask_health_check():
	return 'success'