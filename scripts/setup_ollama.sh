#!/bin/bash

# Ollama Setup Script for Ubuntu (Non-interactive / Network Restricted)

# Configuration
OLLAMA_VERSION="v0.5.7"
INSTALL_DIR="$HOME/DRSEC/bin"
OLLAMA_BIN="$INSTALL_DIR/ollama"
# Using ghproxy mirror for faster download in restricted networks
DOWNLOAD_URL="https://mirror.ghproxy.com/https://github.com/ollama/ollama/releases/download/${OLLAMA_VERSION}/ollama-linux-amd64"

echo "🚀 Starting Ollama Setup..."
echo "📂 Install Directory: $INSTALL_DIR"

# 1. Create directory
mkdir -p "$INSTALL_DIR"

# 2. Download Binary
if [ -f "$OLLAMA_BIN" ]; then
    echo "ℹ️  Ollama binary already exists. Skipping download."
else
    echo "⬇️  Downloading Ollama ${OLLAMA_VERSION}..."
    echo "   Source: $DOWNLOAD_URL"
    
    curl -L --connect-timeout 30 --retry 3 --progress-bar "$DOWNLOAD_URL" -o "$OLLAMA_BIN"
    
    if [ $? -ne 0 ]; then
        echo "❌ Download failed! Please check your network or try downloading manually."
        exit 1
    fi
fi

# 3. Make executable
chmod +x "$OLLAMA_BIN"
echo "✅ Ollama installed successfully!"

# 4. Instructions
echo ""
echo "🎉 Setup Complete!"
echo "---------------------------------------------------"
echo "1. Start Ollama Server in a separate terminal:"
echo "   $OLLAMA_BIN serve"
echo ""
echo "2. In another terminal, pull and run the model:"
echo "   $OLLAMA_BIN run qwen2.5:3b"
echo "---------------------------------------------------"
