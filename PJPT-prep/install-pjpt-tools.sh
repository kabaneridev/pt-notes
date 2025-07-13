#!/bin/bash

echo "🚀 PJPT Tools Installation Script"
echo "================================="
echo ""
echo "This script will install essential tools for PJPT exam"
echo ""

# Check if running on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📱 Detected macOS"
    echo ""
    echo "Installing tools via Homebrew and pip..."
    echo ""
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found! Please install it first:"
        echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    # Install Python and tools
    brew install python3 hashcat nmap
    
    # Install Python tools
    pip3 install impacket
    pip3 install bloodhound
    pip3 install crackmapexec
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐧 Detected Linux"
    echo ""
    
    # Check if Kali Linux
    if grep -q "kali" /etc/os-release 2>/dev/null; then
        echo "🐉 Kali Linux detected - using apt"
        echo ""
        
        sudo apt update
        sudo apt install -y \
            python3-impacket \
            impacket-scripts \
            responder \
            crackmapexec \
            bloodhound \
            hashcat \
            mitm6 \
            nmap \
            enum4linux \
            smbclient \
            smbmap
            
    else
        echo "📦 Generic Linux - using pip"
        echo ""
        
        # Install via pip
        pip3 install impacket
        pip3 install bloodhound
        pip3 install crackmapexec
        pip3 install mitm6
    fi
fi

echo ""
echo "📥 Downloading additional tools..."
echo ""

# Create tools directory
mkdir -p ~/pjpt-tools
cd ~/pjpt-tools

# Download PowerSploit for PowerView
if [ ! -d "PowerSploit" ]; then
    echo "Downloading PowerSploit..."
    git clone https://github.com/PowerShellMafia/PowerSploit.git
fi

# Download Nishang
if [ ! -d "nishang" ]; then
    echo "Downloading Nishang..."
    git clone https://github.com/samratashok/nishang.git
fi

# Download PEASS
if [ ! -f "winPEASx64.exe" ]; then
    echo "Downloading WinPEAS..."
    wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
fi

if [ ! -f "linpeas.sh" ]; then
    echo "Downloading LinPEAS..."
    wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
    chmod +x linpeas.sh
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "📋 Installed tools:"
echo "   - Impacket Suite (psexec, secretsdump, etc.)"
echo "   - Responder (Linux only)"
echo "   - CrackMapExec / NetExec"
echo "   - BloodHound Python"
echo "   - Hashcat"
echo "   - mitm6"
echo "   - PowerSploit (in ~/pjpt-tools)"
echo "   - Nishang (in ~/pjpt-tools)"
echo "   - WinPEAS/LinPEAS (in ~/pjpt-tools)"
echo ""
echo "🔍 Run ./check-impacket.sh to verify installation"
echo ""
echo "Good luck on your PJPT exam! 🎯" 