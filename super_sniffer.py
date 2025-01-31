import psutil
import pyshark
import time
import subprocess
import yaml
import logging
from logging.handlers import RotatingFileHandler

def load_config(config_path="config.yaml"):
    try:
        with open(config_path, "r") as file:
            return yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Failed to load configuration file: {e}")
        exit(1)

def setup_logging(log_file, log_level, max_log_size, backup_count):
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    handler = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count)
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

def ssh_check(process_name):
    for proc in psutil.process_iter(['name']):
        try:
            if process_name.lower() in proc.info['name'].lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
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

    network_interface = config["network"]["interface"]
    known_services = config["network"]["known_services"]
    process_name = config["processes"]["ssh_check"]

    packet_count = config["sniffer"]["packet_count"]
    idle_threshold = config["sniffer"]["idle_threshold"]
    idle_checks = config["sniffer"]["idle_checks"]
    idle_wait_seconds = config["sniffer"]["idle_wait_seconds"]

    wake_time = config["suspend"]["wake_time"]
    suspend_command = config["suspend"]["suspend_command"]

    logging.info("Starting network monitoring script.")

    if ssh_check(process_name):
        logging.info("SSH is running, will not suspend.")
        return

    logging.info("SSH is not running. Checking network usage.")
    
    average_packet_size, captured_ips_list = super_sniffer(network_interface, packet_count)
    
    if sizer(network_interface, average_packet_size, known_services, captured_ips_list, idle_threshold, idle_checks, idle_wait_seconds):
        log_system_info()
        try:
            subprocess.run(suspend_command, shell=True, check=True)
            logging.info(f"System is suspending until {wake_time}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to execute suspension command: {e}")

if __name__ == '__main__':
    main()