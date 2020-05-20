import ipwhois
import info
from scapy.layers.inet import traceroute



class TracertSolver:
    def __init__(self, addr):
        self.output = b""
        self.path = []
        self.ips = []
        self.addr = addr
        self.traceroute()
        self.str_output = self.output.decode("utf-8")
        self.infos = []
        self.generate_whois()

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

    def traceroute(self):
        result, unans = traceroute(self.addr, maxttl=20, timeout=30, verbose=False)
        for snd, rcv in result:
            self.ips.append(rcv.src)
            if rcv.src == self.addr:
                break


if __name__ == '__main__':
    inp = input()
    ts = TracertSolver(inp)
