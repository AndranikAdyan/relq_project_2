import argparse
import parser
import connections
import utils

def main():
	start = utils.datetime.now()
	args_parser = argparse.ArgumentParser()
	args = parser.parse_args(args_parser)
	udp_ports = 0
	tcp_ports = 0
	tcp_scan = []
	udp_scan = []
	utils.print_info(args["ip"])
	if args["sT"]:
		tcp_ports, tcp_scan = connections.check_tcp_connection(args["ip"], args["p"])
	if args["sU"]:
		udp_ports, udp_scan = connections.check_udp_connection(args["ip"], args["p"])
	utils.print_connections(tcp_scan, udp_scan, args, tcp_ports, udp_ports)
	total_time = (utils.datetime.now() - start).total_seconds()
	print(f"Nmap done: 1 IP address (1 host up) scanned in {total_time:.2f}s")

if __name__ == "__main__":
	main()