import subprocess
import os
import json
from loguru import logger as l

TEMP_FILE_NAME = "tmp/volatility-output.json"

# Lista ESTESA di plugin di Volatility 3 (il massimo possibile)
VOLATILITY_PLUGINS = {
    "windows.pslist": "List active processes",
    "windows.pstree": "Show process tree",
    "windows.netscan": "Scan open network connections",
    "windows.cmdline": "Show command lines of processes",
    "windows.dlllist": "List loaded DLLs",
    "windows.driverscan": "Scan for loaded drivers",
    "windows.handles": "List open handles",
    "windows.getsids": "Show security identifiers (SIDs)",
    "windows.svcscan": "Scan Windows services",
    "windows.registry.hivelist": "List loaded registry hives",
    "windows.registry.printkey": "Print a registry key",
    "windows.registry.userassist": "Show UserAssist entries",
    "windows.registry.shimcache": "Analyze application compatibility cache",
    "windows.registry.amcache": "Analyze Amcache registry entries",
    "windows.malfind": "Detect malicious memory regions",
    "windows.memmap": "Show memory mapping",
    "windows.modscan": "Scan for loaded kernel modules",
    "windows.mutantscan": "Scan for mutexes",
    "windows.ssdt": "Show System Service Descriptor Table (SSDT)",
    "windows.callbacks": "Show kernel callbacks",
    "windows.apihooks": "Detect API hooks",
    "windows.syscalls": "Analyze system calls",
    "windows.privileges": "Show process privileges",
    "windows.threads": "List active threads",
    "windows.modules": "List loaded kernel modules",
    "windows.ldrmodules": "Detect unlinked DLLs",
    "windows.bigpools": "Show large memory pools",
    "windows.mbrscan": "Scan Master Boot Record (MBR) for anomalies",
    "windows.vadinfo": "Show Virtual Address Descriptor (VAD) information",
    "windows.mapped_files": "List memory-mapped files",
    "windows.poolscanner": "Scan for memory pool allocations",
    "windows.atomscan": "Scan for atom table entries",
    "windows.devicetree": "List device drivers",
    "windows.mftscan": "Scan Master File Table (MFT) records",
    "windows.driverirp": "Show IRP handlers for drivers",
    "windows.pte": "Show Page Table Entries (PTE)",
    "windows.registry.shellbags": "Analyze ShellBags registry entries",
    "windows.hashdump": "Dump NTLM hashes",
    "windows.dumpfiles": "Extract files from memory",
    "windows.eventlog": "Analyze Windows event logs",
    "windows.pcapdump": "Dump network traffic to a PCAP file",
    "windows.filescan": "Scan for files in memory",
}

class VolatilityController:
    def __init__(self):
        self.temp_file = TEMP_FILE_NAME

    def run_plugin(self, dump_path, plugin):
        if plugin not in VOLATILITY_PLUGINS:
            l.error(f"Plugin {plugin} not supported.")
            return None
        
        command = [
            "volatility3",
            "-f",
            dump_path,
            plugin,
            "--output",
            "json",
            "--output-file",
            self.temp_file,
        ]
        
        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with open(self.temp_file, "r") as file:
                return json.load(file)
        except Exception as e:
            l.error(f"Error executing {plugin}: {e}")
            return None
