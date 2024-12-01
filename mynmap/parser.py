import argparse
import utils

def parse_args(parser: object) -> dict:
	args = {
		"sT":	True,
		"sU":	False,
		"p":	[],
		"ip":	""
	}
	parser.add_argument("-sT", action="store_false", help="TCP scan")
	parser.add_argument("-sU", action="store_true", help="UDP scan")
	parser.add_argument("-p", "--port", type=str, default="1-1000", help="Porst for scan")
	parser.add_argument("ip", type=str, help="Target IP")
	argv = parser.parse_args()

	if argv.ip == "":
		print("Input ip or url for scaning")
		exit(1)
	if argv.sU:
		args["sU"] = True
		args["sT"] = True
	if argv.sU and argv.sT:
		args["sU"] = True
		args["sT"] = False

	args["p"] = utils.parse_ports(argv.port)
	args["ip"] = argv.ip

	return args