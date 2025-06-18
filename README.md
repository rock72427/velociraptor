# Velociraptor 🦖

**Automated Penetration Testing Reconnaissance Tool**

Velociraptor is a comprehensive Python library designed to automate various penetration testing reconnaissance tasks. It's built specifically for Kali Linux environments (including WSL) and provides a fast, efficient, and organized approach to security reconnaissance.

## 🚀 Features

### 🔧 Automatic Dependency Management
- **Tool Detection**: Automatically checks for required penetration testing tools
- **Smart Installation**: Installs missing tools using appropriate package managers (apt, pip, go, git)
- **Comprehensive Toolset**: Supports 30+ popular security tools

### 🎯 Reconnaissance Tasks
1. **Subdomain Enumeration** - Using subfinder, amass, assetfinder
2. **Port Scanning** - Nmap and masscan integration
3. **Screenshot Capture** - Eyewitness and aquatone
4. **Directory Brute-Forcing** - FFUF and gobuster
5. **JavaScript Analysis** - Linkfinder and gospider
6. **Parameter Discovery** - Paramspider and arjun
7. **XSS Detection** - Dalfox and XSStrike
8. **SQL Injection** - SQLMap automation
9. **SSRF Discovery** - Gopherus integration
10. **LFI/RFI Detection** - Fimap and LFISuite
11. **Open Redirect Detection** - Custom payload testing
12. **Security Headers Check** - Nikto and custom analysis
13. **API Reconnaissance** - Kiterunner integration
14. **Content Discovery** - GAU and waybackurls
15. **S3 Bucket Enumeration** - AWS bucket discovery
16. **CMS Enumeration** - CMSeek integration
17. **WAF Detection** - Wafw00f integration
18. **Information Disclosure** - GitDumper and sensitive file checks
19. **Reverse Shell Generation** - MSFvenom automation
20. **Mass Exploitation** - Metasploit framework integration
21. **Vulnerability Scanning** - Nuclei integration
22. **Subdomain Takeover** - Subjack integration
23. **Endpoint Analysis** - Comprehensive URL analysis
24. **Technology Detection** - Framework and technology identification

### 📁 Organized Output
- **Structured Folders**: Each recon task gets its own directory
- **Comprehensive Reports**: Detailed findings in markdown format
- **Logging**: Complete audit trail of all activities
- **Error Handling**: Graceful failure handling with detailed error messages

## 🛠️ Installation

### Prerequisites
- **Kali Linux** (or WSL with Kali)
- **Python 3.7+**
- **Git**
- **Go** (for Go-based tools)
- **Sudo privileges** (for tool installation)

### Quick Start

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/velociraptor.git
cd velociraptor
```

2. **Install Python dependencies**:
```bash
pip3 install -r requirements.txt
```

3. **Run Velociraptor**:
```bash
python3 velociraptor.py example.com
```

## 📖 Usage

### Basic Usage
```bash
python3 velociraptor.py target.com
```

### Advanced Usage
```python
from velociraptor import Velociraptor

# Create Velociraptor instance
velociraptor = Velociraptor("target.com")

# Run full reconnaissance
velociraptor.run_full_recon()

# Or run individual tasks
velociraptor.subdomain_enumeration()
velociraptor.port_scanning()
velociraptor.vulnerability_scanning()
```

## 📁 Output Structure

```
Velociraptor_target.com/
├── subdomain_enumeration/
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── assetfinder.txt
│   └── all_subdomains.txt
├── port_scan/
│   ├── nmap_target_com.txt
│   └── masscan.json
├── screenshot_capture/
│   ├── eyewitness/
│   └── aquatone/
├── directory_bruteforce/
│   ├── ffuf_target_com.json
│   └── gobuster_target_com.txt
├── javascript_analysis/
│   └── linkfinder_*.html
├── parameter_discovery/
│   ├── paramspider.txt
│   └── arjun.json
├── xss_detection/
│   ├── dalfox.txt
│   └── xsstrike.txt
├── sql_injection/
│   └── sqlmap/
├── ssrf_discovery/
│   └── gopherus_output.txt
├── lfi_rfi_detection/
│   └── fimap.txt
├── open_redirect_detection/
│   └── redirect_payloads.txt
├── security_headers_check/
│   ├── nikto.txt
│   └── security_headers.txt
├── api_recon/
│   └── kiterunner.txt
├── content_discovery/
│   ├── gau.txt
│   └── waybackurls.txt
├── s3_bucket_enumeration/
│   ├── bucket_names.txt
│   └── accessible_buckets.txt
├── cms_enumeration/
│   └── cmseek/
├── waf_detection/
│   └── wafw00f.txt
├── information_disclosure/
│   ├── sensitive_files.txt
│   └── git_dump/
├── reverse_shell_generation/
│   ├── windows_reverse.exe
│   ├── linux_reverse.elf
│   └── php_reverse.php
├── mass_exploitation/
│   ├── exploit.rc
│   └── msf_output.txt
├── vulnerability_scanning/
│   └── nuclei.txt
├── subdomain_takeover/
│   └── subjack.txt
├── endpoint_analysis/
│   └── all_endpoints.txt
├── technology_detection/
│   └── technologies.txt
├── recon_summary.md
├── FINAL_REPORT.md
└── velociraptor.log
```

## 🛡️ Supported Tools

### Subdomain Enumeration
- **subfinder** - Fast subdomain discovery
- **amass** - Comprehensive subdomain enumeration
- **assetfinder** - Subdomain discovery from various sources

### Port Scanning
- **nmap** - Network discovery and security auditing
- **masscan** - Fast port scanner

### Web Application Testing
- **ffuf** - Fast web fuzzer
- **gobuster** - Directory/file brute-forcing
- **eyewitness** - Website screenshot capture
- **aquatone** - Visual reconnaissance tool

### Vulnerability Scanning
- **nuclei** - Fast vulnerability scanner
- **nikto** - Web server scanner
- **sqlmap** - SQL injection testing
- **dalfox** - XSS scanner
- **XSStrike** - Advanced XSS detection

### Content Discovery
- **gau** - Fetch known URLs from AlienVault's Open Threat Exchange
- **waybackurls** - Fetch URLs from Wayback Machine
- **gospider** - Fast web crawler

### API Testing
- **kiterunner** - API endpoint discovery
- **arjun** - Parameter discovery

### Cloud Security
- **AWSBucketDump** - S3 bucket enumeration

### CMS & WAF Detection
- **cmseek** - CMS detection and exploitation
- **wafw00f** - Web Application Firewall detection

### Information Gathering
- **linkfinder** - JavaScript endpoint discovery
- **paramspider** - Parameter discovery
- **GitDumper** - Git repository dumping

### Exploitation
- **msfvenom** - Payload generation
- **metasploit** - Exploitation framework

## ⚙️ Configuration

### Environment Variables
```bash
export VELOCIRAPTOR_TIMEOUT=300  # Command timeout in seconds
export VELOCIRAPTOR_THREADS=10    # Number of concurrent threads
export VELOCIRAPTOR_VERBOSE=true  # Enable verbose logging
```

### Custom Wordlists
You can specify custom wordlists for directory brute-forcing:
```python
velociraptor.custom_wordlists = [
    "/path/to/custom/wordlist.txt",
    "/path/to/another/wordlist.txt"
]
```

## 🔧 Customization

### Adding New Tools
```python
# Add new tool to required_tools dictionary
self.required_tools['newtool'] = {
    'apt': 'newtool',
    'check': 'newtool --version'
}

# Add new recon task
def new_recon_task(self):
    """Custom reconnaissance task."""
    folder = os.path.join(self.base_dir, 'new_task')
    os.makedirs(folder, exist_ok=True)
    
    # Your custom logic here
    pass
```

### Custom Payloads
```python
# Add custom XSS payloads
custom_xss_payloads = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>"
]

# Add custom SQL injection payloads
custom_sql_payloads = [
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--"
]
```

## 📊 Reporting

### Generated Reports
1. **recon_summary.md** - Quick overview of findings
2. **FINAL_REPORT.md** - Comprehensive analysis
3. **velociraptor.log** - Detailed execution log

### Report Sections
- Executive Summary
- Tools Status
- Key Findings
- Directory Structure
- Next Steps
- Recommendations

## 🚨 Security Considerations

### Legal Compliance
- **Authorization Required**: Only use on systems you own or have explicit permission to test
- **Scope Definition**: Clearly define the scope of testing
- **Documentation**: Keep records of authorization and findings

### Best Practices
- **Rate Limiting**: Respect target system resources
- **Error Handling**: Graceful failure handling
- **Logging**: Complete audit trail
- **Data Protection**: Secure storage of sensitive findings

## 🐛 Troubleshooting

### Common Issues

1. **Tool Installation Failures**
   ```bash
   # Update package lists
   sudo apt update
   
   # Install build dependencies
   sudo apt install build-essential git curl wget
   ```

2. **Permission Errors**
   ```bash
   # Ensure proper permissions
   sudo chown -R $USER:$USER /usr/local/bin
   ```

3. **Go Tool Issues**
   ```bash
   # Update Go
   go version
   go get -u all
   ```

4. **Python Dependencies**
   ```bash
   # Upgrade pip
   pip3 install --upgrade pip
   
   # Install dependencies
   pip3 install -r requirements.txt
   ```

### Debug Mode
```bash
# Enable debug logging
export VELOCIRAPTOR_DEBUG=true
python3 velociraptor.py target.com
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/yourusername/velociraptor.git
cd velociraptor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**This tool is for authorized penetration testing and security research only. Users take full responsibility for any actions performed using this tool. The author accepts no liability for damage caused by this tool. If you do not accept these conditions, do not use this tool.**

## 🙏 Acknowledgments

- **Kali Linux Team** - For the excellent penetration testing distribution
- **Tool Authors** - For creating the amazing security tools integrated here
- **Security Community** - For continuous research and development

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/velociraptor/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/velociraptor/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/velociraptor/wiki)

---

**Made with ❤️ for the security community** 