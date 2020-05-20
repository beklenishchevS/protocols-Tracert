import socket
import subprocess
import re
import ipwhois
import info
import argparse
import sys
import random
from icmplib import ICMPRequest


# TODO:
#  1. сделать тайм-аут для traceroute
#  2. добавить argparse

class TracertSolver:
    def __init__(self, addr):
        self.output = b""
        self.path = []
        self.addr = addr
        self.generate_file()
        self.run_bash()
        self.str_output = self.output.decode("utf-8")
        self.ips = []
        self.infos = []
        self.parce_traceroute()
        self.generate_whois()

    def parce_traceroute(self):
        self.ips = re.findall(r"\d+\.\d+\.\d+\.\d+", self.str_output)

    def generate_file(self):
        with open("icmp.sh", "w") as bash:
            bash.write(f"#!/usr/bin/env bash\ntraceroute {self.addr}")

    def generate_whois(self):
        for idx, ip in enumerate(self.ips):
            self.run_whois(ip, idx)


    def run_whois(self, ip, idx):
        try:
            proc = ipwhois.ipwhois.IPWhois(ip)
            whois = proc.lookup_whois()
            i = info.Info()
            i.set_info(ip, whois, idx+1)
        except Exception as e:
            i = info.Info()
            i.set_info(ip, None, idx+1, e)
        print(i.generate_reply())


    def run_bash(self):
        proc = subprocess.Popen('./icmp.sh', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.output = proc.stdout.read()



if __name__ == '__main__':
    inp = input()
    ts = TracertSolver(inp)
