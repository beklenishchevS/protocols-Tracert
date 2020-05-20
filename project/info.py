import re
import string
LOCAL = []

class Info:
    def __init__(self):
        self.AS = None
        self.country = None
        self.name = None
        self.exception = ""
        self.num = None
        self.ip = None
        self.local = False

    def set_info(self, ip, whois, number, exception=""):
        self.ip = [int(k) for k in ip.split(".")]
        self.local = self.is_ip_local()
        try:
            self.AS = whois["asn"]
        except Exception:
            pass
        try:
            self.country = whois['asn_country_code']
        except Exception:
            pass
        try:
            self.name = whois["nets"][0]["name"]
        except Exception:
            pass
        self.exception = exception
        self.num = number

    def generate_reply(self):
        reply = ''
        ip = [str(i) for i in self.ip]
        if self.local:
            reply = str(self.num) + " " + str(".".join(ip)) + "\nlocal"
        elif self.exception == "":
            reply = str(self.num) + " " + str(".".join(ip)) + f"\n{self.name} {self.AS} {self.country}"
        else:
            reply = str(self.num) + " " + str(".".join(ip)) + f"\n*"
        return reply


    def is_ip_local(self):
        if self.ip is None:
            return False

        if self.ip[0] == 10:
            return True

        if self.ip[0] == 172 and self.ip[1] < 32 and self.ip[1] > 15:
            return True

        if self.ip[0] == 192 and self.ip[1] == 168:
            return True

        return False
