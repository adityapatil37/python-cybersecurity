import sys
import argparse
from scapy.all import ICMP, IP, sr1
from netaddr import IPNetwork
import concurrent.futures
import logging

def ping_host(host, timeout):
    response = sr1(IP(dst=str(host))/ICMP(), timeout=timeout, verbose=0)
    return str(host) if response else None

def ping_sweep(network, netmask, timeout):
    live_hosts = []
    ip_network = IPNetwork(f"{network}/{netmask}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(ping_host, host, timeout): host for host in ip_network.iter_hosts()}

        for future in concurrent.futures.as_completed(future_to_ip):
            host = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    live_hosts.append(result)
                    print(f"Host {result} is online.")
            except Exception as exc:
                print(f"Host {host} generated an exception: {exc}")

    return live_hosts

def main():
    parser = argparse.ArgumentParser(description="Ping Sweep Script")
    parser.add_argument("network", type=str, help="Network address (e.g., 192.168.1.0)")
    parser.add_argument("netmask", type=str, help="Netmask (e.g., 24)")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout in seconds (default: 1)")
    parser.add_argument("--logfile", type=str, help="Log file to save results")

    args = parser.parse_args()

    logging.basicConfig(filename=args.logfile, level=logging.INFO, format='%(asctime)s %(message)s')

    live_hosts = ping_sweep(args.network, args.netmask, args.timeout)
    print("\nScan completed.")
    print(f"Live hosts: {live_hosts}")

    if args.logfile:
        logging.info(f"Live hosts: {live_hosts}")

if __name__ == "__main__":
    main()
