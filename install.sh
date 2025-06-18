#!/bin/bash

# Velociraptor Installation Script
# Automated Penetration Testing Reconnaissance Tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

print_status "Starting Velociraptor installation..."

# Check if we're on a supported system
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    print_status "Detected Linux system"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    print_error "macOS is not fully supported. Please use Kali Linux or WSL."
    exit 1
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.7+ first."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    print_error "Python 3.7+ is required. Current version: $PYTHON_VERSION"
    exit 1
fi

print_success "Python $PYTHON_VERSION detected"

# Check if Git is installed
if ! command -v git &> /dev/null; then
    print_warning "Git is not installed. Installing..."
    sudo apt update
    sudo apt install -y git
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_warning "Go is not installed. Installing..."
    sudo apt update
    sudo apt install -y golang-go
fi

# Create tools directory
TOOLS_DIR="$HOME/velociraptor-tools"
mkdir -p "$TOOLS_DIR"
export PATH="$PATH:$HOME/go/bin"

print_status "Installing Python dependencies..."

# Upgrade pip
python3 -m pip install --upgrade pip

# Install Python requirements
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
else
    print_warning "requirements.txt not found. Installing basic dependencies..."
    pip3 install requests beautifulsoup4 colorama
fi

print_status "Installing system dependencies..."

# Update package list
sudo apt update

# Install essential packages
sudo apt install -y \
    build-essential \
    curl \
    wget \
    unzip \
    nmap \
    masscan \
    nikto \
    sqlmap \
    wafw00f \
    dirb \
    gobuster \
    seclists

print_status "Installing Go-based tools..."

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/meg@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/haccer/subjack@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/hakluke/hakrawler@latest

print_status "Cloning Git repositories..."

# Clone tool repositories
cd "$TOOLS_DIR"

# Clone repositories
git clone https://github.com/GerbenJavado/LinkFinder.git || print_warning "LinkFinder already exists"
git clone https://github.com/s0md3v/XSStrike.git || print_warning "XSStrike already exists"
git clone https://github.com/devanshbatham/ParamSpider.git || print_warning "ParamSpider already exists"
git clone https://github.com/tarunkant/Gopherus.git || print_warning "Gopherus already exists"
git clone https://github.com/D35m0nd142/LFISuite.git || print_warning "LFISuite already exists"
git clone https://github.com/Tuhinshubhra/CMSeeK.git || print_warning "CMSeeK already exists"
git clone https://github.com/arthaud/git-dumper.git || print_warning "git-dumper already exists"
git clone https://github.com/1ndianl33t/Gf-Patterns.git || print_warning "Gf-Patterns already exists"

# Install Python-based tools
print_status "Installing Python-based tools..."

# Install eyewitness
pip3 install eyewitness

# Install arjun
pip3 install arjun

# Install fimap (if available)
if command -v apt &> /dev/null; then
    sudo apt install -y fimap || print_warning "fimap not available in repositories"
fi

# Install aquatone
go install github.com/michenriksen/aquatone@latest

print_status "Setting up environment..."

# Add Go bin to PATH permanently
if ! grep -q "export PATH.*go/bin" ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    print_status "Added Go bin to PATH in ~/.bashrc"
fi

# Set environment variable for tools directory
if ! grep -q "VELOCIRAPTOR_TOOLS_DIR" ~/.bashrc; then
    echo "export VELOCIRAPTOR_TOOLS_DIR=$TOOLS_DIR" >> ~/.bashrc
    print_status "Added VELOCIRAPTOR_TOOLS_DIR to ~/.bashrc"
fi

# Make velociraptor.py executable
chmod +x velociraptor.py

print_success "Installation completed successfully!"
echo
print_status "Next steps:"
echo "1. Restart your terminal or run: source ~/.bashrc"
echo "2. Test the installation: python3 velociraptor.py --help"
echo "3. Run a scan: python3 velociraptor.py example.com"
echo
print_status "📚 Documentation: https://github.com/rock72427/velociraptor"
print_status "🐛 Issues: https://github.com/rock72427/velociraptor/issues" 