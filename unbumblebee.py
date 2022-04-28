# PE-Sieve Integration by @hasherezade

import os
import sys
import re
import json
import ipaddress
import argparse 
import traceback
import threading
import subprocess
import signal

parser = argparse.ArgumentParser(description='Bumblebee Loader C2\'s Extractor Through PE-Sieve by @hasherezade')
parser.add_argument('--pid', dest='target_pid', type=int, help='PID of the process running the Bumblebee Loader', required=True)
parser.add_argument('--o', dest='output_file', type=str, help='Filename of the output file')
parser.add_argument('--is32bit',action='store_true', help='Specify this flag if the target process is a 32-bit process')

OUTPUT_DIR_PREFIX = "process_"
IPV4_PORT_REGEX = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})"
IPV4_REGEX = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

class PESieve(object):
    active = False

    def __init__(self, workingDir="", is64bit=True):
        if not workingDir:
            self.workingDir = os.getcwd()
        else:
            self.workingDir = workingDir
        if is64bit:
            self.peSieve = os.path.join(self.workingDir, 'tools/pe-sieve64.exe'.replace("/", os.sep))
        else:
            self.peSieve = os.path.join(self.workingDir, 'tools/pe-sieve32.exe'.replace("/", os.sep))
        if self.isAvailable():
            self.active = True
        else:
            print("Cannot find PE-Sieve in expected location {0} ".format(self.peSieve))
    
    def runProcess(self, command, timeout=10):
        output = ""
        returnCode = 0

        # Kill check
        kill_check = threading.Event()
        def _kill_process_after_a_timeout(pid):
            os.kill(pid, signal.SIGTERM)
            kill_check.set()
            print("[+] timeout hit - killing pid {0}".format(pid))
            return "", 1
        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            returnCode = e.returncode
            traceback.print_exc()
        pid = p.pid
        watchdog = threading.Timer(timeout, _kill_process_after_a_timeout, args=(pid, ))
        watchdog.start()
        stdout = p.communicate()[0].decode('utf-8').strip()
        stderr = p.communicate()[1].decode('utf-8').strip()
        watchdog.cancel()
        success = not kill_check.isSet()
        kill_check.clear()
        return stdout, returnCode
        
    def isAvailable(self):
        if not os.path.exists(self.peSieve):
            print("[+] PE-Sieve not found in location '{0}'. Feature will not be active...\n".format(self.peSieve))
            return False
        print("[+] PE-Sieve found in location '{0}'\n".format(self.peSieve))    
        return True

    def scan(self, pid):
        # Compose command
        command = [self.peSieve, '/pid', str(pid), '/quiet', '/dmode', '1', '/json', '/minidmp']
        # Run PE-Sieve on given process
        output, returnCode = self.runProcess(command)

        # Inspect output files
        c2_list = []
        ipv4_list = []
        pesieve_output_dir = os.path.join(self.workingDir, OUTPUT_DIR_PREFIX + str(pid) + os.sep)
        pesieve_output = json.loads(output)
        report_scans = pesieve_output["scans"]
        # Search for headers scans 
        print("[+] Scanning for suspicious injected headers\n")    
        for scan in report_scans:
            if "headers_scan" in scan:
                suspicious_header_scan = scan["headers_scan"]
                # Search for injected DLL's with replaced PE and modified EP
                if suspicious_header_scan["is_pe_replaced"] == 1 and suspicious_header_scan["ep_modified"] == 1:
                    # Open injected DLL dump from local PE-sieve dump
                    injected_dll_module = suspicious_header_scan["module"]
                    injected_dll_module_file = suspicious_header_scan["module_file"].split(os.sep)[-1]
                    injected_dll = open(os.path.join(pesieve_output_dir, injected_dll_module + "." + injected_dll_module_file), 'rb')
                    print("[+] Found an injected payload with PE replaced and EP modified named '{0}'\n".format(injected_dll_module_file))    
                    data = injected_dll.read()
                    data = data.decode("ansi")
                    injected_dll.close()
                    # Search for IPV4:PORT regex matches
                    current_c2_matches = [":".join(x) for x in re.findall(IPV4_PORT_REGEX, data)]
                    for c2_matches in current_c2_matches:
                        c2_list.append(c2_matches.strip())
                        ipv4_list.append(c2_matches.split(":")[0].strip())
                    # Search for IPV4 regex matches 
                    current_c2_matches = re.findall(IPV4_REGEX, data)
                    for c2_matches in current_c2_matches:
                        if not ipaddress.ip_address(c2_matches).is_private and c2_matches not in c2_list and c2_matches not in ipv4_list:
                            c2_list.append(c2_matches.strip())

        return c2_list, ipv4_list

def write_results(args, c2_matches, ipv4_matches):
    # print on file if the -o flag is specified
    if args.output_file:
        file = open(args.output_file, "w+")
        file.write("Bumblebee Loader Extracted C2's: \n")
        file.write("\n".join(c2.strip() for c2 in c2_matches))
        file.write("\n\n")
        file.write("Bumblebee Loader Extracted IPv4's: \n")
        file.write("\n".join(ipv4.strip() for ipv4 in ipv4_matches))
    # print on the command-line
    print("[+] Bumblebee Loader Extracted C2's:")
    print("\n".join(c2.strip() for c2 in c2_matches))
    print("\n[+] Bumblebee Loader Extracted IPv4's:")
    print("\n".join(ipv4.strip() for ipv4 in ipv4_matches))


def main():
    args = parser.parse_args()
    
    # Start the PE-Sieve instance
    pesieve_instance = None 
    if args.is32bit:
        pesieve_instance = PESieve(is64bit=False)
    else: 
        pesieve_instance = PESieve()
    
    # Scan the given process PID
    c2_matches = []
    ipv4_matches = []
    if pesieve_instance.active:
        c2_matches, ipv4_matches = pesieve_instance.scan(pid=args.target_pid)
    # Store results in a output file or print in the command-line
    if len(c2_matches) > 0 or len(ipv4_matches) > 0:
        write_results(args, c2_matches, ipv4_matches)
    else:
        print("[+] Bumblebee Loader C2's or IPv4's not found")

        
if __name__ == "__main__":  
    main()
