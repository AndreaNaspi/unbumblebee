# unbumblebee.py
Python script to extract the C&C configuration from an active Bumblebee process through PE-Sieve.

Based on [PE-Sieve](https://github.com/hasherezade/pe-sieve) work made by [@hasherezade](https://github.com/hasherezade).

# Configuration
To extract the Bumblebee configuration you need a safe environment (such as a virtualized system) with an installed Python 3.7 or higher.  

:warning: Be sure to make a snapshot of the environment before proceeding with the execution of the Bumblebee DLL! :warning:

Once cloned the repository, trigger the execution of the Bumblebee Loader DLL (for example through the Windows utility rundll32.exe) specifying the export which leads to the execution of the malware (such as 'IternalJob'):  
```
C:\unbumblebee> rundll32.exe bumblebee.dll,IternalJob
```
Find the PID of the running Bumblebee process (for example through Process Hacker) and run the Python script to extract the C&C configuration:
```
C:\unbumblebee> python3 unbumblebee.py --pid 3628
[+] PE-Sieve found in location 'C:\unbumblebee\tools\pe-sieve64.exe'

[+] Scanning for suspicious injected headers

[+] Found an injected payload with PE replaced and EP modified named 'GdiPlus.dll'

[+] Bumblebee Loader Extracted C2's:
45.147.229.177:443

[+] Bumblebee Loader Extracted IPv4's:
45.147.229.177
```

For further script arguments execute the script with the --help flag:
```
C:\unbumblebee> python3 unbumblebee.py --help

options:
  -h, --help        show this help message and exit
  --pid TARGET_PID  PID of the process running the Bumblebee Loader
  --o OUTPUT_FILE   Filename of the output file
  --is32bit         Specify this flag if the target process is a 32-bit process
```
