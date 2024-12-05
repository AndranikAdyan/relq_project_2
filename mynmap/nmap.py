#!/usr/bin/env python3

import argparse
import parser
import connections
import utils

def main():
	start = utils.datetime.now()
	args_parser = argparse.ArgumentParser()
	args = parser.parse_args(args_parser)
	udp_open_ports = 0
	tcp_open_ports = 0
	tcp_scan = []
	udp_scan = []
	utils.print_info(args["host"])
	if args["sT"]:
		tcp_open_ports, tcp_scan = connections.check_tcp_connection(args["host"], args["p"])
	elif args["sS"]:
		tcp_open_ports, tcp_scan = connections.check_syn_connection(args["host"], args["p"])
	if args["sU"]:
		udp_open_ports, udp_scan = connections.check_udp_connection(args["host"], args["p"])
	utils.print_connections(tcp_scan, udp_scan, args, tcp_open_ports, udp_open_ports)
	total_time = (utils.datetime.now() - start).total_seconds()
	print(f"Nmap done: 1 IP address (1 host up) scanned in {total_time:.2f}s")

if __name__ == "__main__":
	main()
