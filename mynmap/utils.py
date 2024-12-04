from datetime import datetime

def print_info(host: str) -> None:
	print(f"Starting scanning at {datetime.now().strftime("%Y-%m-%d %H:%M")}")
	print(f"Nmap scan report for {host}")

def get_service(port: int, protocol: str) -> str:
	if protocol == "tcp":
		file = open("./lists/tcp_services")
	elif protocol == "udp":
		file = open("./lists/udp_services")
	else:
		return -1
	for line in file:
		if str(port) == line.split("\t")[1].split("/")[0]:
			file.close()
			return line.split("\t")[0]
	file.close()
	return "unknown"

def print_connections(tcp_scan, udp_scan, args, tcp_ports, udp_ports) -> None:
	if len(tcp_scan) != 0 or len(udp_scan) != 0:
		print("PORT\tSTATE\tSERVICE")
	scans_len = len(udp_scan) + len(tcp_scan)
	for el in tcp_scan:
		if "close" in el and scans_len <= 26:
			print(el)
		elif "close" not in el:
			print(el)
	for el in udp_scan:
		if "close" in el and scans_len <= 26:
			print(el)
		elif "close" not in el:
			print(el)
	if args["sT"]:
		print(f"Not shown: {len(args['p']) - tcp_ports} close tcp ports (no-response)")
	if args["sU"]:
		print(f"Not shown: {len(args['p']) - udp_ports} close udp ports (no-response)")