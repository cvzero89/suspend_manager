import os
import time
import subprocess
import psutil
import pyshark
import yaml
import logging
from logging.handlers import RotatingFileHandler

def load_config(config_path=f"{os.path.abspath(os.path.dirname(__file__))}/config.yaml"):
    try:
        with open(config_path, "r") as file:
            return yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Failed to load configuration file: {e}")
        exit(1)

def setup_logging(log_file, log_level, max_log_size, backup_count):
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    log_file_location = f'{os.path.abspath(os.path.dirname(__file__))}/{log_file}'
    handler = RotatingFileHandler(log_file_location, maxBytes=max_log_size, backupCount=backup_count)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[handler, logging.StreamHandler()]
    )

def log_system_info():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    disk_usage = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()

    logging.info(f"System Stats Before Suspension:")
    logging.info(f"  - CPU Usage: {cpu_usage}%")
    logging.info(f"  - Memory Usage: {memory_info.percent}% ({memory_info.used / (1024**3):.2f} GB used)")
    logging.info(f"  - Disk Usage: {disk_usage.percent}% ({disk_usage.used / (1024**3):.2f} GB used)")
    logging.info(f"  - Network Sent: {net_io.bytes_sent / (1024**2):.2f} MB, Received: {net_io.bytes_recv / (1024**2):.2f} MB")

def process_check(process_name, process_user):
    for proc in psutil.process_iter(['pid', 'name', 'username']):  
        try:
            if not psutil.pid_exists(proc.pid):  
                continue

            proc_info = proc.as_dict(attrs=['name', 'username'], ad_value=None)  

            proc_name = proc_info.get('name', "").lower()
            proc_user = proc_info.get('username', "").lower() 

            if proc_name == process_name.lower() and proc_user == process_user.lower():
                logging.info(f"Found process '{process_name}' running under user '{process_user}' (PID: {proc.pid})")
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logging.warning(f"Could not access process {proc.pid}: {e}")

    return False

def super_sniffer(network_interface, packet_count):
    capture = pyshark.LiveCapture(interface=network_interface)
    captured_packet_list = []
    captured_ips_list = []

    try:
        for packet in capture.sniff_continuously(packet_count=packet_count):
            try:
                protocol = packet.transport_layer
                src_addr = packet.ip.src
                src_port = packet[protocol].srcport
                dst_addr = packet.ip.dst
                dst_port = packet[protocol].dstport
                packet_size = int(packet.captured_length)

                if packet_size >= 67:
                    captured_packet_list.append(packet_size)
                    captured_ips_list.extend([f"{src_addr}:{src_port}", f"{dst_addr}:{dst_port}"])
                    logging.info(f"Packet: {src_addr}:{src_port} -> {dst_addr}:{dst_port} | {protocol} | Size: {packet_size}")
            except AttributeError:
                pass  

        if captured_packet_list:
            average_packet_size = sum(captured_packet_list) / len(captured_packet_list)
        else:
            average_packet_size = 0  

    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
        average_packet_size, captured_ips_list = 0, []

    return average_packet_size, captured_ips_list

def sizer(network_interface, average_packet_size, known_services, captured_ips_list, idle_threshold, idle_checks, idle_wait_seconds, packet_count):
    if average_packet_size >= idle_threshold:
        logging.info(f"{network_interface} is active. Average packet size: {average_packet_size}. Not suspending.")
        return False

    logging.info(f"{network_interface} is idle. Average packet size: {average_packet_size}.")

    if any(ip in known_services for ip in captured_ips_list):
        logging.info("Known services detected. Monitoring for more idle periods.")
        idle_score = 0

        while idle_score < idle_checks:
            time.sleep(idle_wait_seconds)
            average_packet_size, captured_ips_list = super_sniffer(network_interface, packet_count)

            if average_packet_size <= idle_threshold:
                idle_score += 1
                logging.info(f"Idle count: {idle_score}. Average packet size: {average_packet_size}.")
            else:
                logging.info("Network activity resumed. No suspension.")
                return False

    logging.info("No known services active. Preparing to suspend.")
    return True

def main():
    config = load_config()
    setup_logging(config["logging"]["log_file"], config["logging"]["log_level"], config["logging"]["max_log_size"], config["logging"]["backup_count"])

    network_interface = config["network"].get("interface", "eth0")
    known_services = config["network"].get("known_services", [])
    processes_check = config["processes_check"].get("enabled", False)

    packet_count = config["sniffer"].get("packet_count", 500)
    idle_threshold = config["sniffer"].get("idle_threshold", 700)
    idle_checks = config["sniffer"].get("idle_checks", 3)
    idle_wait_seconds = config["sniffer"].get("idle_wait_seconds", 300)

    wake_time = config["suspend"].get("wake_time", "07:00")
    mode = config["suspend"].get("mode", "mem")
    time_or_date = config["suspend"].get("time_or_date", "--date")
    suspend_command = f"/usr/sbin/rtcwake -m {mode} -l {time_or_date} {wake_time}"

    logging.info("Starting network monitoring script.")

    if processes_check is True:
        processes_name = config["processes_check"].get("processes", [])
        for key in processes_name.keys():
            process_name = config["processes_check"]["processes"][key]["name"]
            process_user = config["processes_check"]["processes"][key]["user"]
            if process_check(process_name, process_user):
                logging.info(f'{process_name} is running, will not suspend.')
                exit(1)

    logging.info("Specified processes are not running. Checking network usage.")

    average_packet_size, captured_ips_list = super_sniffer(network_interface, packet_count)

    if sizer(network_interface, average_packet_size, known_services, captured_ips_list, idle_threshold, idle_checks, idle_wait_seconds, packet_count):
        log_system_info()
        try:
            subprocess.run(suspend_command, shell=True, check=True)
            logging.info(f"System is suspending until {wake_time}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to execute suspension command: {e}")

if __name__ == '__main__':
    main()