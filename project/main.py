from tracert_solver import TracertSolver
import argparse

def check_correct_ip(ip):
    try:
        nums_of_ip = [int(i) for i in ip.split(".")]
    except ValueError:
        return False
    if len(nums_of_ip) != 4:
        return False
    for i in nums_of_ip:
        if i > 255 or i < 0:
            return False
    return True


parser = argparse.ArgumentParser()
parser.add_argument("ip", type=str)
args = parser.parse_args()
ip = args.ip
if check_correct_ip(ip):
    ts = TracertSolver(ip)
else:
    print(f"{ip} is invalid")
