from datetime import datetime

def port_is_valid(ports: str) -> bool:
	line_count = 0
	for i in ports:
		if i == '-':
			line_count += 1
		if not i.isdigit() and i != '-' and i != ',' or (line_count > 1):
			return False
	return True

def parse_ports(ports: str) -> list:
	if not port_is_valid(ports):
		print("Invalid argument for -p")
		exit (1)
	if ports == '-':
		return [i for i in range(1, 65536)]
	if '-' in ports:
		nums = ports.split('-')
		return [i for i in range(int(nums[0]), int(nums[1]) + 1)]
	if ',' in ports:
		ports_arr = ports.split(',')
		ports_arr = list(map(lambda s: int(s), ports_arr))
		return ports_arr
	return [int(ports)]

def print_info(ip: str) -> None:
	print(f"Starting scanning at {datetime.now().strftime("%Y-%m-%d %H:%M")}")
	print(f"Nmap scan report for {ip}")

def get_service(port: int, protocol: str) -> str:
	if protocol == "tcp":
		file = open("./lists/tcp_services")
	elif protocol == "udp":
		file = open("./lists/udp_services")
	else:
		return -1
	for line in file:
		if str(port) == line.split("\t")[1].split("/")[0]:
			service = line.split("\t")[0]
			break
	else:
		return "unknown"
	file.close()
	return service

def print_connections(tcp_scan, udp_scan, args, tcp_ports, udp_ports) -> None:
	if len(tcp_scan) != 0 or len(udp_scan) != 0:
		print("PORT\tSTATE\tSERVICE")
	for el in tcp_scan:
		if "close" in el and len(el) <= 26:
			print(el)
		else:
			print(el)
	for el in udp_scan:
		if "close" in el and len(el) <= 26:
			print(el)
		else:
			print(el)
	if args["sT"]:
		print(f"Not shown: {len(args['p']) - tcp_ports} close tcp ports (no-response)")
	if args["sU"]:
		print(f"Not shown: {len(args['p']) - udp_ports} close udp ports (no-response)")