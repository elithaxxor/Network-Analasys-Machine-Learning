import asyncio
import os
import re
import sys
import logging
import subprocess
import json
import platform
import socket
import ipaddress
import random
import string
import aiofiles
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, Union, Tuple
from datetime import datetime
from enum import Enum

# ---- Tool Description Utility ----

class ToolDescription:
    """Utility class to provide descriptions of security tools"""
    
    @staticmethod
    def get_description(tool_name: str) -> str:
        """Get description for a specific security tool"""
        descriptions = {
            'nmap': (
                "Nmap (Network Mapper) is a free and open-source network scanner used to discover hosts and services "
                "on a computer network. It sends packets and analyzes the responses to discover hosts, open ports, "
                "services running, operating systems, and potential vulnerabilities."
            ),
            'sublist3r': (
                "Sublist3r is a Python tool designed to enumerate subdomains of websites using OSINT techniques. "
                "It utilizes search engines, DNS records, and various APIs to discover subdomains quickly. "
                "This helps security professionals identify potential attack surfaces of target domains."
            ),
            'theharvester': (
                "TheHarvester is an OSINT (Open-Source Intelligence) gathering tool designed to collect email addresses, "
                "subdomains, hosts, employee names, open ports, and banners from different public sources like search "
                "engines, PGP key servers, and SHODAN database. It helps in the information gathering phase of penetration tests."
            ),
            'metasploit': (
                "Metasploit is a penetration testing framework that makes hacking simpler. It's an essential tool that "
                "provides a complete environment for penetration testing and extensive capabilities for exploitation, "
                "payload generation, and post-exploitation modules."
            ),
            'proxychains': (
                "ProxyChains is a tool that forces any TCP connection made by any application to go through proxies like "
                "TOR, SOCKS4, SOCKS5, or HTTP(S). It enables users to run network tools through a proxy server for anonymity, "
                "bypassing restrictions, or accessing network resources securely."
            ),
            'ping': (
                "Ping is a basic network diagnostic tool used to test the reachability of a host on an IP network. "
                "It works by sending ICMP echo request packets to the target host and waiting for a response, "
                "measuring round-trip time, and reporting packet loss."
            ),
            'traceroute': (
                "Traceroute is a network diagnostic tool used to track the path of packets from one IP address to another. "
                "It helps identify the route and measuring transit delays of packets across an IP network, providing "
                "information about network hops and latency."
            ),
            'dig': (
                "Dig (Domain Information Groper) is a flexible tool for interrogating DNS name servers. It performs "
                "DNS lookups and displays the answers that are returned from the name servers that were queried. "
                "It's an essential tool for network troubleshooting and security reconnaissance."
            ),
            'ssh': (
                "SSH (Secure Shell) is a cryptographic network protocol for secure data communication, remote command "
                "execution, and other secure network services between two networked computers. In reconnaissance, it can "
                "be used to verify if SSH services are accessible on target systems."
            )
        }
        
        return descriptions.get(tool_name.lower(), f"No description available for {tool_name}")

    @staticmethod
    def print_tool_info(tool_name: str):
        """Print information about a tool to the console"""
        print(f"\n{'=' * 50}")
        print(f"TOOL: {tool_name.upper()}")
        print(f"{'=' * 50}")
        print(ToolDescription.get_description(tool_name))
        print(f"{'=' * 50}\n")


# ---- Subdomain Enumeration ----

class SubdomainEnumerator(BaseScanner):
    """Class for subdomain enumeration using Sublist3r"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 results_dir: str = "recon_results",
                 threads: int = 40, 
                 use_bruteforce: bool = False,
                 verbose: bool = True):
        super().__init__(target, config, None, results_dir)
        self.threads = threads
        self.use_bruteforce = use_bruteforce
        self.verbose = verbose
        
    @property
    def name(self) -> str:
        return "sublist3r"
    
    async def scan(self) -> CommandScanResult:
        """Run Sublist3r for subdomain enumeration"""
        # Print tool information
        ToolDescription.print_tool_info(self.name)
        
        # Ensure target is a domain, not an IP
        if self._is_ip_address(self.target):
            self.logger.warning(f"{self.target} appears to be an IP address, not a domain name. Sublist3r requires a domain name.")
            return CommandScanResult(
                target=self.target,
                scanner_name=self.name,
                command=[],
                success=False,
                message="Cannot run Sublist3r on an IP address. Please provide a domain name."
            )
        
        # Build command
        cmd = ["sublist3r", "-d", self.target, "-t", str(self.threads), "-o"]
        output_file = self.get_output_file()
        cmd.append(output_file)
        
        if self.use_bruteforce:
            cmd.append("-b")
        
        if self.verbose:
            cmd.append("-v")
        
        # Run the command
        self.logger.info(f"Starting subdomain enumeration for {self.target}")
        success, output = await self.executor.execute(cmd, None)
        
        # Ensure the output file exists even if the command didn't create it
        if success and not os.path.exists(output_file):
            try:
                async with aiofiles.open(output_file, "w") as f:
                    if output:
                        # Extract subdomains from output if available
                        subdomains = self._extract_subdomains_from_output(output)
                        if subdomains:
                            await f.write("\n".join(subdomains))
            except Exception as e:
                self.logger.error(f"Error creating output file: {e}")
        
        # Also log subdomains to console
        if os.path.exists(output_file):
            try:
                async with aiofiles.open(output_file, "r") as f:
                    content = await f.read()
                    subdomains = [line.strip() for line in content.splitlines() if line.strip()]
                    if subdomains:
                        print("\nDiscovered Subdomains:")
                        print("-" * 50)
                        for subdomain in subdomains:
                            print(f"  {subdomain}")
                        print("-" * 50)
                        print(f"Total: {len(subdomains)} subdomains found\n")
                    else:
                        print("\nNo subdomains discovered\n")
            except Exception as e:
                self.logger.error(f"Error reading output file: {e}")
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Subdomain enumeration completed successfully" if success else "Subdomain enumeration failed"
        )
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if the target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _extract_subdomains_from_output(self, output: str) -> List[str]:
        """Extract subdomains from Sublist3r output"""
        subdomains = []
        if output:
            # Look for lines that might contain subdomains
            for line in output.splitlines():
                # Sublist3r usually outputs discovered subdomains in a simple format
                if f".{self.target}" in line:
                    subdomain = line.strip()
                    # Basic validation to ensure it looks like a domain
                    if "." in subdomain and not subdomain.startswith("[") and not subdomain.startswith(" "):
                        subdomains.append(subdomain)
        return subdomains


# ---- Basic Network Reconnaissance ----

class NetworkReconBase(BaseScanner):
    """Base class for network reconnaissance"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 results_dir: str = "recon_results"):
        super().__init__(target, config, None, results_dir)
    
    async def is_host_alive(self) -> bool:
        """Check if host is alive using ping"""
        # Different ping command parameters for different operating systems
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "3", "-w", "1000", self.target]
        else:
            cmd = ["ping", "-c", "3", "-W", "1", self.target]
            
        success, output = await self.executor.execute(cmd)
        
        if success and output:
            if "ttl=" in output.lower() or "time=" in output.lower():
                return True
        
        return False
    
    async def try_ssh_handshake(self) -> Tuple[bool, str]:
        """Attempt SSH handshake with the target"""
        # Use the ssh command with timeout and disable strict host key checking
        cmd = [
            "ssh", 
            "-o", "StrictHostKeyChecking=no", 
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            f"user@{self.target}", 
            "exit"
        ]
        
        success, output = await self.executor.execute(cmd)
        
        # Check the output for SSH information
        ssh_version = "Unknown"
        if output:
            # Try to extract SSH version
            ssh_match = re.search(r'SSH-\d+\.\d+-([^\s]+)', output)
            if ssh_match:
                ssh_version = ssh_match.group(1)
        
        # Return whether SSH seems to be open and the version if detected
        if "Connection refused" in output:
            return False, "Connection refused"
        elif "timed out" in output:
            return False, "Connection timed out"
        elif "ssh_exchange_identification" in output:
            return True, ssh_version
        elif "Permission denied" in output:
            return True, ssh_version
        
        return False, "SSH handshake failed or inconclusive"


class PingScanner(NetworkReconBase):
    """Class for basic ping scan"""
    
    @property
    def name(self) -> str:
        return "ping"
    
    async def scan(self) -> CommandScanResult:
        """Perform a ping scan"""
        ToolDescription.print_tool_info(self.name)
        
        # Build the command based on OS
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "4", self.target]
        else:
            cmd = ["ping", "-c", "4", self.target]
            
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        # Parse and display results
        if success and output:
            # Extract packet loss and round-trip times if available
            packet_loss = "Unknown"
            avg_time = "Unknown"
            
            if "packet loss" in output:
                packet_loss_match = re.search(r'(\d+)% packet loss', output)
                if packet_loss_match:
                    packet_loss = f"{packet_loss_match.group(1)}%"
            
            if "avg" in output:
                avg_match = re.search(r'= [^/]*/([^/]*)/[^/]*/[^/]*\s', output)
                if avg_match:
                    avg_time = f"{avg_match.group(1)} ms"
            
            # Print results to console
            print("\nPing Results:")
            print("-" * 50)
            print(f"Target: {self.target}")
            print(f"Status: {'Alive' if 'bytes from' in output or 'Reply from' in output else 'Not responding'}")
            print(f"Packet Loss: {packet_loss}")
            print(f"Average Round-trip Time: {avg_time}")
            print("-" * 50 + "\n")
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Ping scan completed successfully" if success else "Ping scan failed"
        )


class SSHScanner(NetworkReconBase):
    """Class for SSH service detection"""
    
    @property
    def name(self) -> str:
        return "ssh"
    
    async def scan(self) -> CommandScanResult:
        """Perform an SSH handshake attempt"""
        ToolDescription.print_tool_info(self.name)
        
        # Try SSH handshake
        output_file = self.get_output_file()
        is_open, version = await self.try_ssh_handshake()
        
        # Format output
        output = f"SSH Scan Results for {self.target}:\n"
        output += f"SSH Service: {'Available' if is_open else 'Not available'}\n"
        output += f"SSH Version: {version}\n"
        
        # Write to file
        async with aiofiles.open(output_file, "w") as f:
            await f.write(output)
        
        # Print results
        print("\nSSH Scan Results:")
        print("-" * 50)
        print(f"Target: {self.target}")
        print(f"SSH Service: {'Available' if is_open else 'Not available'}")
        print(f"SSH Version: {version}")
        print("-" * 50 + "\n")
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=["ssh", "handshake", "check"],
            output=output,
            output_file=output_file,
            success=True,
            message=f"SSH {'is' if is_open else 'is not'} available on {self.target}"
        )


class TracerouteScanner(NetworkReconBase):
    """Class for traceroute with DNS lookups"""
    
    @property
    def name(self) -> str:
        return "traceroute"
    
    async def scan(self) -> CommandScanResult:
        """Perform a traceroute with DNS lookups"""
        ToolDescription.print_tool_info(self.name)
        
        # Determine the command based on OS
        cmd = []
        if platform.system().lower() == "windows":
            cmd = ["tracert", self.target]
        else:
            cmd = ["traceroute", "-n", self.target]
            
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        # Perform DNS lookups for each hop
        if success and output:
            enhanced_output = await self._enhance_with_dns_lookups(output)
            
            # Write enhanced output to file
            async with aiofiles.open(output_file, "w") as f:
                await f.write(enhanced_output)
            
            # Print summary
            print("\nTraceroute Results:")
            print("-" * 50)
            print(f"Path to {self.target} completed with {enhanced_output.count('Hop #')} hops")
            print(f"Full details saved to: {output_file}")
            print("-" * 50 + "\n")
            
            # Update output for the result
            output = enhanced_output
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Traceroute completed successfully" if success else "Traceroute failed"
        )
    
    async def _enhance_with_dns_lookups(self, traceroute_output: str) -> str:
        """Enhance traceroute output with DNS lookups"""
        enhanced_output = "Traceroute with DNS Lookups\n"
        enhanced_output += "=" * 50 + "\n\n"
        
        # Extract IP addresses from traceroute output
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        hop_number = 0
        for line in traceroute_output.splitlines():
            hop_number += 1
            
            # Skip lines without IP addresses
            ips = re.findall(ip_pattern, line)
            if not ips:
                enhanced_output += f"Hop #{hop_number}: No response\n"
                continue
            
            # Get the first IP in the line
            ip = ips[0]
            
            # Perform DNS lookup
            try:
                cmd = ["dig", "+short", "-x", ip]
                success, dig_output = await self.executor.execute(cmd)
                
                hostname = "No DNS record"
                if success and dig_output and dig_output.strip():
                    hostname = dig_output.strip().rstrip('.')
                
                enhanced_output += f"Hop #{hop_number}: {ip} ({hostname})\n"
                
            except Exception as e:
                enhanced_output += f"Hop #{hop_number}: {ip} (DNS lookup failed: {str(e)})\n"
        
        return enhanced_output


class DNSLookupScanner(NetworkReconBase):
    """Class for comprehensive DNS lookups"""
    
    @property
    def name(self) -> str:
        return "dig"
    
    async def scan(self) -> CommandScanResult:
        """Perform comprehensive DNS lookups"""
        ToolDescription.print_tool_info(self.name)
        
        # Skip if target is an IP address without reverse DNS
        if self._is_ip_address(self.target):
            self.logger.info(f"{self.target} is an IP address, performing reverse DNS lookup")
            return await self._perform_reverse_lookup()
        
        # For domains, perform forward lookups for various record types
        output_file = self.get_output_file()
        
        record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME"]
        
        combined_output = f"DNS Lookup Results for {self.target}\n"
        combined_output += "=" * 50 + "\n\n"
        
        print("\nDNS Lookup Results:")
        print("-" * 50)
        print(f"Target: {self.target}")
        
        for record_type in record_types:
            cmd = ["dig", "+short", self.target, record_type]
            success, output = await self.executor.execute(cmd)
            
            if success:
                result = output.strip() if output and output.strip() else "No records found"
                combined_output += f"{record_type} Records:\n{result}\n\n"
                
                # Print summarized output to console
                record_count = 0 if not output or not output.strip() else len(output.strip().splitlines())
                print(f"{record_type} Records: {record_count} found")
        
        # Write combined output to file
        async with aiofiles.open(output_file, "w") as f:
            await f.write(combined_output)
        
        print("-" * 50)
        print(f"Full DNS details saved to: {output_file}")
        print("-" * 50 + "\n")
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=["dig", "multiple", "records"],
            output=combined_output,
            output_file=output_file,
            success=True,
            message=f"DNS lookup completed for {self.target}"
        )
    
    async def _perform_reverse_lookup(self) -> CommandScanResult:
        """Perform a reverse DNS lookup for an IP address"""
        output_file = self.get_output_file("_reverse")
        cmd = ["dig", "+short", "-x", self.target]
        
        success, output = await self.executor.execute(cmd, output_file)
        
        hostname = "No reverse DNS record found"
        if success and output and output.strip():
            hostname = output.strip().rstrip('.')
        
        # Print results
        print("\nReverse DNS Lookup:")
        print("-" * 50)
        print(f"IP Address: {self.target}")
        print(f"Hostname: {hostname}")
        print("-" * 50 + "\n")
        
        return CommandScanResult(
            target=self.target,
            scanner_name=f"{self.name}_reverse",
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message=f"Reverse DNS lookup completed for {self.target}"
        )
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if the target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False


class StealthyNmapScanner(EnhancedNmapScanner):
    """Class for fast and stealthy Nmap scans"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 credential: Optional[Credential] = None, 
                 results_dir: str = "recon_results"):
        # Configure stealthy preferences
        preferences = NmapPreferences(
            stealth_level=StealthLevel.STEALTHY,
            scan_speed=ScanSpeed.SNEAKY,
            service_detection=True,
            os_detection=False,
            script_scan=False  # No scripts for stealthy scan
        )
        
        super().__init__(target, config, credential, results_dir, preferences)
    
    @property
    def name(self) -> str:
        return "stealthy_nmap"
    
    async def scan(self) -> CommandScanResult:
        """Run a fast, stealthy Nmap scan"""
        ToolDescription.print_tool_info("nmap")
        
        # Override with specific stealth options
        cmd = [
            "nmap", 
            "-sS",               # SYN Stealth scan
            "-Pn",               # Skip host discovery
            "--open",            # Only show open ports
            "-n",                # No DNS resolution
            "--max-retries", "1",  # Minimal retries
            "--host-timeout", "30s",  # Quick timeout
            "-F",                # Fast mode - fewer ports
            self.target
        ]
        
        output_file = self.get_output_file()
        success, output = await self.executor.execute(cmd, output_file)
        
        # Parse and print results
        if success and output:
            # Extract open ports
            open_ports = []
            for line in output.splitlines():
                if "open" in line and "/tcp" in line:
                    port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)?', line)
                    if port_match:
                        port_num = port_match.group(1)
                        service = port_match.group(2) if port_match.group(2) else "unknown"
                        open_ports.append((port_num, service))
            
            # Print results
            print("\nStealthy Nmap Scan Results:")
            print("-" * 50)
            print(f"Target: {self.target}")
            print(f"Open Ports: {len(open_ports)}")
            
            if open_ports:
                print("\nPort  Service")
                print("----- -------")
                for port, service in open_ports:
                    print(f"{port.ljust(5)} {service}")
            
            print("-" * 50 + "\n")
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Stealthy Nmap scan completed successfully" if success else "Stealthy Nmap scan failed"
        )


# ---- The Harvester Class ----

class TheHarvesterScanner(BaseScanner):
    """Class for harvesting emails, subdomains, names and more using theHarvester"""
    
    def __init__(self, target: str, config: ScannerConfig, 
                 results_dir: str = "recon_results",
                 sources: str = "all"):
        super().__init__(target, config, None, results_dir)
        self.sources = sources
    
    @property
    def name(self) -> str:
        return "theharvester"
    
    async def scan(self) -> CommandScanResult:
        """Run theHarvester scan"""
        ToolDescription.print_tool_info(self.name)
        
        # Skip if target is an IP
        if self._is_ip_address(self.target):
            self.logger.warning(f"{self.target} appears to be an IP address. TheHarvester requires a domain name.")
            return CommandScanResult(
                target=self.target,
                scanner_name=self.name,
                command=[],
                success=False,
                message="Cannot run TheHarvester on an IP address. Please provide a domain name."
            )
        
        # Build command
        output_file = self.get_output_file()
        cmd = [
            "theHarvester", 
            "-d", self.target, 
            "-b", self.sources,
            "-f", output_file
        ]
        
        # Run the command
        self.logger.info(f"Starting theHarvester scan for {self.target}")
        success, output = await self.executor.execute(cmd, None)
        
        # Extract and display results
        if success and os.path.exists(output_file):
            try:
                # Read results
                with open(output_file, 'r') as f:
                    content = f.read()
                
                # Count findings
                emails_count = content.count('@')
                hosts_count = len(re.findall(r'[-a-zA-Z0-9]+\.' + re.escape(self.target), content))
                
                # Display summary
                print("\nTheHarvester Results:")
                print("-" * 50)
                print(f"Target: {self.target}")
                print(f"Emails discovered: {emails_count}")
                print(f"Hosts/subdomains discovered: {hosts_count}")
                print(f"Full results saved to: {output_file}")
                print("-" * 50 + "\n")
                
            except Exception as e:
                self.logger.error(f"Error processing TheHarvester results: {e}")
        
        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="TheHarvester scan completed successfully" if success else "TheHarvester scan failed"
        )
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if the target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False


# ---- ProxyChains Manager ----

class ProxyType(Enum):
    """Types of proxies supported by ProxyChains"""
    HTTP = "http"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    TOR = "tor"


class ProxyChainsManager:
    """Class to manage ProxyChains configuration and usage"""
    
    def __init__(self, config_file: str = "/etc/proxychains.conf"):
        self.config_file = config_file
        self.logger = logging.getLogger(self.__class__.__name__)
        self.executor = CommandExecutor(timeout=60)
    
    async def is_installed(self) -> bool:
        """Check if ProxyChains is installed"""
        success, _ = await self.executor.execute(["which", "proxychains"])
        return success
    
    async def install(self, system_type: str) -> bool:
        """Install ProxyChains based on system type"""
        if await self.is_installed():
            self.logger.info("ProxyChains is already installed")
            return True
        
        cmd = []
        if system_type.lower() == "debian":
            cmd = ["apt-get", "update", "&&", "apt-get", "install", "-y", "proxychains"]
        elif system_type.lower() == "darwin":
            cmd = ["brew", "install", "proxychains-ng"]
        else:
            self.logger.error(f"Unsupported system type: {system_type}")
            return False
        
        success, _ = await self.executor.execute(["bash", "-c", " ".join(cmd)])
        return success
    
    async def create_config(self, proxy_type: ProxyType, proxy_host: str, proxy_port: int) -> bool:
        """Create a basic ProxyChains configuration file"""
        config_content = f"""# proxychains.conf generated by SMB Enumeration Tool
# Configuration format:
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')

strict_chain
proxy_dns

remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# add proxy here ...
{proxy_type.value} {proxy_host} {proxy_port}
"""
        
        try:
            # Create config directory if needed
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            # Write config file
            async with aiofiles.open(self.config_file, "w") as f:
                await f.write(config_content)
            
            self.logger.info(f"ProxyChains configuration created at {self.config_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error creating ProxyChains configuration: {e}")
            return False
    
    def prepare_proxychains_command(self, original_cmd: List[str]) -> List[str]:
        """Prepare a command to run through ProxyChains"""
        if not isinstance(original_cmd, list) or not original_cmd:
            raise ValueError("Command must be a non-empty list")
        
        return ["proxychains"] + original_cmd


# ---- Network Reconnaissance Strategy ----

class NetworkReconStrategy(ScanStrategy):
    """Strategy for basic network reconnaissance"""
    
    def __init__(self, target: str, config: ScannerConfig, results_dir: str = "recon_results",
                use_proxychains: bool = False, proxy_config: Dict = None):
        super().__init__(target, config, results_dir)
        self.use_proxychains = use_proxychains
        self.proxy_config = proxy_config or {}
        self.proxy_manager = None
        
        if self.use_proxychains:
            self.proxy_manager = ProxyChainsManager()
    
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute the network reconnaissance strategy"""
        self.logger.info(f"Starting network reconnaissance for {self.target}")
        results = AggregatedResult(self.target)
        
        # Set up proxychains if requested
        if self.use_proxychains:
            await self._setup_proxychains()
        
        # Create scanners for basic network recon
        ping_scanner = PingScanner(self.target, self.config, self.results_dir)
        ssh_scanner = SSHScanner(self.target, self.config, self.results_dir)
        traceroute_scanner = TracerouteScanner(self.target, self.config, self.results_dir)
        dns_scanner = DNSLookupScanner(self.target, self.config, self.results_dir)
        nmap_scanner = StealthyNmapScanner(self.target, self.config, credential, self.results_dir)
        
        # 1. First check if the host is alive
        is_alive = await ping_scanner.is_host_alive()
        ping_result = await ping_scanner.scan()
        results.add_result(ping_result)
        
        # 2. If alive, continue with other scans
        if is_alive:
            # Run all scans
            ssh_result = await ssh_scanner.scan()
            results.add_result(ssh_result)
            
            traceroute_result = await traceroute_scanner.scan()
            results.add_result(traceroute_result)
            
            dns_result = await dns_scanner.scan()
            results.add_result(dns_result)
            
            nmap_result = await nmap_scanner.scan()
            results.add_result(nmap_result)
            
            # Parse Nmap results to get SMB info
            if nmap_result.success and hasattr(nmap_scanner, "parse_results"):
                try:
                    nmap_info = await nmap_scanner.parse_results(nmap_result.output_file)
                    
                    # Merge nmap_info into results.smb_info
                    results.smb_info.shares.extend(nmap_info.shares)
                    results.smb_info.users.update(nmap_info.users)
                    results.smb_info.vulnerabilities.extend(nmap_info.vulnerabilities)
                    results.smb_info.protocols.extend(nmap_info.protocols)
                    
                    if nmap_info.os_info:
                        results.smb_info.os_info.update(nmap_info.os_info)
                        
                except Exception as e:
                    self.logger.error(f"Error parsing Nmap results: {e}")
        else:
            self.logger.warning(f"Host {self.target} appears to be down, skipping further scans")
        
        # Save report
        report_file = os.path.join(self.results_dir, f"network_recon_{self.target}.json")
        await results.save_to_file(report_file)
        self.logger.info(f"Network reconnaissance complete, report saved to {report_file}")
        
        return results
    
    async def _setup_proxychains(self) -> bool:
        """Set up ProxyChains for anonymous scanning"""
        if not self.proxy_manager:
            self.logger.error("Proxy manager is not initialized")
            return False
        
        # Check if ProxyChains is installed
        if not await self.proxy_manager.is_installed():
            # Determine system type
            system_type = "debian"  # Default
            if platform.system().lower() == "darwin":
                system_type = "darwin"
            
            # Ask user for confirmation
            print(f"\nProxyChains is not installed. Would you like to install it for {system_type.capitalize()}?")
            choice = input("Enter Y/N: ").strip().lower()
            
            if choice == 'y':
                success = await self.proxy_manager.install(system_type)
                if not success:
                    self.logger.error("Failed to install ProxyChains")
                    return False
            else:
                self.logger.warning("ProxyChains installation skipped. Continuing without proxies.")
                return False
        
        # Create custom configuration if needed
        if self.proxy_config:
            proxy_type = ProxyType[self.proxy_config.get("type", "SOCKS5").upper()]
            proxy_host = self.proxy_config.get("host", "127.0.0.1")
            proxy_port = int(self.proxy_config.get("port", 9050))
            
            success = await self.proxy_manager.create_config(proxy_type, proxy_host, proxy_port)
            if not success:
                self.logger.error("Failed to create ProxyChains configuration")
                return False
        
        self.logger.info("ProxyChains set up successfully")
        return True


# ---- OSINT Strategy ----

class OSINTStrategy(ScanStrategy):
    """Strategy for OSINT (Open Source Intelligence) gathering"""
    
    def __init__(self, target: str, config: ScannerConfig, results_dir: str = "recon_results",
                use_sublist3r: bool = True, use_harvester: bool = True):
        super().__init__(target, config, results_dir)
        self.use_sublist3r = use_sublist3r
        self.use_harvester = use_harvester
    
    async def execute(self, credential: Optional[Credential] = None) -> AggregatedResult:
        """Execute the OSINT gathering strategy"""
        self.logger.info(f"Starting OSINT gathering for {self.target}")
        results = AggregatedResult(self.target)
        
        # Run subdomain enumeration if requested
        if self.use_sublist3r:
            sublist3r_scanner = SubdomainEnumerator(self.target, self.config, self.results_dir)
            sublist3r_result = await sublist3r_scanner.scan()
            results.add_result(sublist3r_result)
        
        # Run TheHarvester if requested
        if self.use_harvester:
            harvester_scanner = TheHarvesterScanner(self.target, self.config, self.results_dir)
            harvester_result = await harvester_scanner.scan()
            results.add_result(harvester_result)
        
        # Save report
        report_file = os.path.join(self.results_dir, f"osint_{self.target}.json")
        await results.save_to_file(report_file)
        self.logger.info(f"OSINT gathering complete, report saved to {report_file}")
        
        return results


# ---- Command Line Interface ----

async def main_async():
    """Main async entry point with extended reconnaissance functionality"""
    parser = argparse.ArgumentParser(description="Enhanced Network Reconnaissance and Vulnerability Assessment Tool")
    parser.add_argument("-t", "--targets", nargs="+", required=True, help="Target IP address(es) or domain(s)")
    parser.add_argument("-u", "--username", type=str, help="Username for authentication")
    parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--results-dir", type=str, default="recon_results", help="Directory to store results")
    
    # Add strategy options
    strategy_group = parser.add_argument_group("Scan Strategy")
    strategy_group.add_argument("--strategy", type=str, 
                               choices=["network_recon", "smb_enum", "vulnerability", "osint", "all"], 
                               default="network_recon", help="Scanning strategy to use")
    
    # Add network recon options
    recon_group = parser.add_argument_group("Network Reconnaissance")
    recon_group.add_argument("--skip-ping", action="store_true", help="Skip ping scan")
    recon_group.add_argument("--skip-ssh", action="store_true", help="Skip SSH scan")
    recon_group.add_argument("--skip-traceroute", action="store_true", help="Skip traceroute")
    recon_group.add_argument("--skip-dns", action="store_true", help="Skip DNS lookups")
    recon_group.add_argument("--skip-nmap", action="store_true", help="Skip Nmap scan")
    
    # Add OSINT options
    osint_group = parser.add_argument_group("OSINT Options")
    osint_group.add_argument("--sublist3r", action="store_true", help="Use Sublist3r for subdomain enumeration")
    osint_group.add_argument("--harvester", action="store_true", help="Use TheHarvester for OSINT gathering")
    osint_group.add_argument("--harvester-sources", type=str, default="all", 
                            help="Sources to use with TheHarvester (comma-separated)")
    
    # Add proxychains options
    proxy_group = parser.add_argument_group("Proxy Options")
    proxy_group.add_argument("--use-proxy", action="store_true", help="Use ProxyChains for all scans")
    proxy_group.add_argument("--proxy-type", type=str, choices=["http", "socks4", "socks5", "tor"], 
                            default="socks5", help="Proxy type to use with ProxyChains")
    proxy_group.add_argument("--proxy-host", type=str, default="127.0.0.1", help="Proxy host")
    proxy_group.add_argument("--proxy-port", type=int, default=9050, help="Proxy port")
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("recon.log"),
            logging.StreamHandler()
        ]
    )
    
    # Load config
    config = await SMBScannerConfig.from_yaml(args.config)
    
    # Ask about proxy usage if not specified
    if not args.use_proxy:
        print("\nWould you like to route scans through ProxyChains for anonymity?")
        print("Note: This can make scans slower but helps hide your identity")
        choice = input("Use ProxyChains? (y/N): ").strip().lower()
        args.use_proxy = choice == 'y'
    
    # Setup proxy configuration if requested
    proxy_config = None
    if args.use_proxy:
        proxy_config = {
            "type": args.proxy_type,
            "host": args.proxy_host,
            "port": args.proxy_port
        }
    
    # Create credential if provided
    credential = None
    if args.username or args.password:
        credential = Credential(args.username or "", args.password or "")
    
    # Run appropriate strategy based on selection
    results = {}
    
    for target in args.targets:
        if args.strategy == "network_recon" or args.strategy == "all":
            network_strategy = NetworkReconStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir,
                use_proxychains=args.use_proxy,
                proxy_config=proxy_config
            )
            results[f"{target}_network"] = await network_strategy.execute(credential)
        
        if args.strategy == "osint" or args.strategy == "all" or args.sublist3r or args.harvester:
            osint_strategy = OSINTStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir,
                use_sublist3r=args.sublist3r or args.strategy == "osint" or args.strategy == "all",
                use_harvester=args.harvester or args.strategy == "osint" or args.strategy == "all"
            )
            results[f"{target}_osint"] = await osint_strategy.execute()
        
        if args.strategy == "smb_enum" or args.strategy == "all":
            print("\nRunning SMB enumeration...")
            enumerator = SMBEnumerator(
                targets=[target],
                config=config,
                username=args.username,
                password=args.password,
                results_dir=args.results_dir
            )
            
            if await enumerator.validate_environment():
                smb_results = await enumerator.run("intelligent")
                results.update(smb_results)
            else:
                logging.error("SMB enumeration environment validation failed")
        
        if args.strategy == "vulnerability" or args.strategy == "all":
            print("\nRunning vulnerability scan...")
            vuln_strategy = VulnerabilityScanStrategy(
                target=target,
                config=config,
                results_dir=args.results_dir,
                use_metasploit=True,
                aggressive=False
            )
            
            if await enumerator.validate_environment():
                results[f"{target}_vuln"] = await vuln_strategy.execute(credential)
            else:
                logging.error("Vulnerability scanning environment validation failed")
    
    # Generate combined report
    if results:
        report_generator = ReportGenerator(args.results_dir)
        await report_generator.print_summary(results)
        
        # Generate detailed report with all scan types
        combined_report_file = os.path.join(args.results_dir, f"combined_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        await report_generator.save_full_report(results, combined_report_file)
        logging.info(f"Combined report saved to {combined_report_file}")


def main():
    """Entry point for the script"""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
