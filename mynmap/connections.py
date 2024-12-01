import socket
import utils

def check_tcp_connection(host: str, ports: list) -> int:
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
		else:
			if len(ports) <= 26:
				service = utils.get_service(port, "tcp")
				tcp_arr.append(f"{port}/tcp\tclose\t{service}")
		sock.close()
	return open_ports, tcp_arr

def check_udp_connection(host: str, ports: list) -> str:
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