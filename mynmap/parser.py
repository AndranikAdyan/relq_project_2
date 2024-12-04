import socket

def port_error():
	print("The specified ports are out of the valid range")
	exit(1)

def port_is_valid(ports: str) -> bool:
	if ports == '-':
		return True
	line_count = 0
	for i in ports:
		if i == '-':
			line_count += 1
		if not i.isdigit() and i != '-' and i != ',' or (line_count > 1):
			return False

	if '-' in ports and ',' in ports:
		return False

	if '-' in ports:
		nums = ports.split('-')
		if int(nums[0]) < 1 or int(nums[1]) > 65535 or int(nums[0]) > int(nums[1]):
			return False
	elif ',' in ports:
		ports_arr = ports.split(',')
		ports_arr = list(map(lambda s: int(s), ports_arr))
		for port in ports_arr:
			if port < 1 or port > 65535:
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

def parse_args(parser: object) -> dict:
	args = {
		"sT":	True,
		"sU":	False,
		"p":	[],
		"host":	""
	}
	parser.add_argument("-sT", action="store_false", help="TCP scan")
	parser.add_argument("-sU", action="store_true", help="UDP scan")
	parser.add_argument("-sS", action="store_true", help="TCP SYN scan")
	parser.add_argument("host", type=str, help="Target host")
	parser.add_argument("-p", "--port", type=str, default="1-1000", help="Porst for scan")
	argv = parser.parse_args()

	if argv.host == "":
		print("Input host for scaning")
		exit(1)
	if argv.sU:
		args["sU"] = True
		args["sT"] = True
	if argv.sU and argv.sT:
		args["sU"] = True
		args["sT"] = False

	args["p"] = parse_ports(argv.port)
	args["host"] = argv.host

	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(1)
		sock.connect((args["host"], 80))
	except socket.gaierror:
		print("Name or service not found")
		exit(1)

	return args