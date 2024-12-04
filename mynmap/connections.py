import socket
import utils
from scapy.all import IP, TCP, sr1, send, conf # type: ignore

def check_tcp_connection(host: str, ports: list[int]) -> tuple[int, list[str]]:
	tcp_arr = []
	open_ports = 0
	for port in ports:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(0.5)
		result = sock.connect_ex((host, port))
		if result == 0:
			service = utils.get_service(port, "tcp")
			tcp_arr.append(f"{port}/tcp\topen\t{service}")
			open_ports += 1
		elif result == 110:
			service = utils.get_service(port, "tcp")
			tcp_arr.append(f"{port}/tcp\tfiltered\t{service}")
		elif len(ports) <= 26:
				service = utils.get_service(port, "tcp")
				tcp_arr.append(f"{port}/tcp\tclose\t{service}")
		sock.close()
	return open_ports, tcp_arr

def check_udp_connection(host: str, ports: list[int]) -> tuple[int, list[str]]:
	open_ports = 0
	udp_arr = []
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		for port in ports:
			sock.settimeout(0.5)
			sock.sendto(b"", (host, port))
			try:
				sock.recvfrom(1024)
				service = utils.get_service(port, "udp")
				udp_arr.append(f"{port}/udp\topen\t{service}")
				open_ports += 1
			except Exception:
				if len(ports) <= 26:
					service = utils.get_service(port, "udp")
					udp_arr.append(f"{port}/udp\tclose\t{service}")
	return open_ports, udp_arr

def check_syn_connection(host: str, ports: list[int]) -> tuple[int, list[str]]:
	conf.verb = 0
	open_ports = 0
	syn_arr = []
	ip_layer = IP(dst=host)
	for port in ports:
		tcp_syn = TCP(dport=port, flags='S')
		syn_packet = ip_layer / tcp_syn

		response = sr1(syn_packet, timeout=0.1)
		if response and response[TCP].flags == "SA" and response.haslayer(TCP):
			open_ports += 1
			service = utils.get_service(port, "tcp")
			syn_arr.append(f"{port}/udp\topen\t{service}")

			tcp_rst = TCP(dport=port, sport=response[TCP].sport, flags="R")
			rst_packet = ip_layer / tcp_rst
			send(rst_packet)
		elif len(ports) <= 26:
			service = utils.get_service(port, "udp")
			syn_arr.append(f"{port}/udp\tclose\t{service}")
	return open_ports, syn_arr