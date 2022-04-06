import psutil

processName = 'ssh'
## My laptop automatically connects, I might be creating backups or needing info, if so I do not want the server to suspend:
def ssh_check(processName): 
	for proc in psutil.process_iter():
		try:
			if processName.lower() in proc.name().lower():
				return True
		except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
				pass
	return False

check_ssh = ssh_check(processName)

if check_ssh == True:
	print('SSH is running, will not suspend.')
	exit()
else:
	print('SSH is not running, will check network usage.')

import pyshark
import time

# define interface
networkInterface = "eth0"

# define capture object
capture = pyshark.LiveCapture(interface=networkInterface)

print(f'listening on {networkInterface}')

captured_packet_list = []
captured_ips_list = []

def super_sniffer():

	for packet in capture.sniff_continuously(packet_count=1000):
	    # adjusted output
	    try:
	        # get timestamp
	        localtime = time.asctime(time.localtime(time.time()))

	        # get packet content
	        protocol = packet.transport_layer   # protocol type
	        src_addr = packet.ip.src            # source address
	        src_port = packet[protocol].srcport   # source port
	        dst_addr = packet.ip.dst            # destination address
	        dst_port = packet[protocol].dstport   # destination port
	        ip_port_src = f'{packet.ip.src}:{src_port}'
	        ip_port_dst = f'{packet.ip.dst}:{dst_port}'
	        packet_size = int(packet.captured_length)
	        if packet_size >= 67:
		        captured_packet_list.append(packet_size)
		        captured_ips_list.append(ip_port_src)
		        captured_ips_list.append(ip_port_dst)
		        # output packet info
		        print (f'{localtime} source: {src_addr}:{src_port} IP to: {dst_addr} {protocol} size: {packet_size}')
	    except AttributeError as e:
	        # ignore packets other than TCP, UDP and IPv4
	        pass
	the_sum = sum(captured_packet_list)
	the_number_of_elements = len(captured_packet_list)
	average_packet_size = the_sum / the_number_of_elements		        

	return average_packet_size, captured_ips_list

average_packet_size, captured_ips_list = super_sniffer()

## Re-running packet capture if known services are running (?)
## Known (possibly) running services:
service_1 = 'x.x.x.x'
service_2 = 'x.x.x.x'
service_3 = 'x.x.x.x'
service_4 = 'x.x.x.x'
known_services = [service_1, service_2, service_3, service_4]

idle_score = 0

if average_packet_size >= 700:
	print(f'{networkInterface} is in use. Average packet size is: {average_packet_size}.')
	exit()
else:
	print(f'{networkInterface} is idle. Average packet size is: {average_packet_size}.')
	if any(elem in known_services for elem in captured_ips_list):
		print('Found known services. Sniffer will run again:')
		while idle_score < 3:
			time.sleep(300)
			average_packet_size, captured_ips_list = super_sniffer()
			if average_packet_size <= 700:
				idle_score += 1
				print(f'Sniffer has run {idle_score} times, still no activity. Average packet size is: {average_packet_size}.')
			elif average_packet_size >= 700:
				print(f'Sniffer ran {idle_score} times, found activity on the network. Not suspending today.')
				idle_score = 5
        exit()
	else:
		print('There are no known services running. We can suspend now.')


import subprocess

command_to_sleep_wake = "/usr/sbin/rtcwake -m disk -l -t $(date +%s -d 'tomorrow 07:00')"

subprocess.Popen([command_to_sleep_wake], shell=True)
