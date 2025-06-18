#!/bin/bash

# Velociraptor Installation Script
# This script installs Velociraptor and its dependencies on Kali Linux

set -e

echo "🦖 Velociraptor Installation Script"
echo "=================================="

# Check if running on Kali Linux
if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    echo "⚠️  Warning: This script is designed for Kali Linux"
    echo "   Some tools may not install correctly on other distributions"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "❌ Please do not run this script as root"
    echo "   Run as a regular user with sudo privileges"
    exit 1
fi

# Update system
echo "📦 Updating system packages..."
sudo apt update

# Install basic dependencies
echo "🔧 Installing basic dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    build-essential \
    golang-go \
    nmap \
    masscan \
    nikto \
    sqlmap \
    wafw00f \
    fimap

# Install Go tools
echo "🚀 Installing Go-based tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/haccer/subjack@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/meg@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
export PATH=$PATH:$(go env GOPATH)/bin

# Install Python tools
echo "🐍 Installing Python-based tools..."
pip3 install --user eyewitness arjun

# Clone Git repositories
echo "📚 Cloning tool repositories..."
cd /tmp

# LinkFinder
git clone https://github.com/GerbenJavado/LinkFinder.git
sudo cp -r LinkFinder /opt/
sudo chmod +x /opt/LinkFinder/linkfinder.py

# XSStrike
git clone https://github.com/s0md3v/XSStrike.git
sudo cp -r XSStrike /opt/
sudo chmod +x /opt/XSStrike/xsstrike.py

# ParamSpider
git clone https://github.com/devanshbatham/ParamSpider.git
sudo cp -r ParamSpider /opt/
sudo chmod +x /opt/ParamSpider/paramspider.py

# Gopherus
git clone https://github.com/tarunkant/Gopherus.git
sudo cp -r Gopherus /opt/
sudo chmod +x /opt/Gopherus/gopherus.py

# LFISuite
git clone https://github.com/D35m0nd142/LFISuite.git
sudo cp -r LFISuite /opt/
sudo chmod +x /opt/LFISuite/lfi.py

# CMSeek
git clone https://github.com/Tuhinshubhra/CMSeeK.git
sudo cp -r CMSeeK /opt/
sudo chmod +x /opt/CMSeeK/cmseek.py

# GitDumper
git clone https://github.com/arthaud/git-dumper.git
sudo cp -r git-dumper /opt/
sudo chmod +x /opt/git-dumper/git-dumper.py

# Gf-Patterns
git clone https://github.com/1ndianl33t/Gf-Patterns.git
mkdir -p ~/.gf
cp -r Gf-Patterns/* ~/.gf/

# Install Velociraptor
echo "🦖 Installing Velociraptor..."
cd ~
if [ -d "velociraptor" ]; then
    echo "📁 Velociraptor directory already exists, updating..."
    cd velociraptor
    git pull
else
    echo "📁 Cloning Velociraptor..."
    git clone https://github.com/yourusername/velociraptor.git
    cd velociraptor
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Make velociraptor.py executable
chmod +x velociraptor.py

# Create symlink
sudo ln -sf $(pwd)/velociraptor.py /usr/local/bin/velociraptor

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "🎉 Velociraptor is now ready to use!"
echo ""
echo "Usage:"
echo "  velociraptor target.com"
echo "  python3 velociraptor.py target.com"
echo ""
echo "📁 Tools installed in:"
echo "  - Go tools: $(go env GOPATH)/bin"
echo "  - Python tools: ~/.local/bin"
echo "  - Git tools: /opt/"
echo ""
echo "🔧 Next steps:"
echo "  1. Restart your terminal or run: source ~/.bashrc"
echo "  2. Test installation: velociraptor --help"
echo "  3. Start reconnaissance: velociraptor example.com"
echo ""
echo "📚 Documentation: https://github.com/yourusername/velociraptor"
echo "" 