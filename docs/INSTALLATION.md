# 📦 Installation Guide - HexStrike AI

## 🎯 **Setup Order (Follow Exactly)**

### **Step 1: Docker Desktop** 🐳
1. Install Docker Desktop
2. Build HexStrike AI container
3. Verify container health

### **Step 2: LM Studio** 🤖  
1. Download LM Studio
2. Install DeepSeek V3 model
3. Start local server (port 1234)

### **Step 3: VS Code Integration** 💻
1. Install Continue extension
2. Configure with provided config.json
3. Test AI connection

## **Detailed Steps**

### **1. Docker Setup**
```bash
# Build container
docker build -t hexstrike-ai:v2 .

# Run container  
docker run -d --name hexstrike-ai -p 8888:8888 hexstrike-ai:v2

# Test health
curl http://localhost:8888/health
```

### **2. LM Studio Setup**
1. Download from lmstudio.ai
2. Install "deepseek-coder-v2-lite-instruct" model
3. Start server on port 1234
4. Test: `curl http://localhost:1234/v1/models`

### **3. VS Code Setup**
1. Install Continue extension
2. Copy `.continue/config.json` to VS Code
3. Press Ctrl+Shift+P → "Continue: Open"
4. Test with security scan prompt

## **Verification**
- ✅ Container: `docker ps`
- ✅ LM Studio: `curl localhost:1234/v1/models`  
- ✅ Tools: `docker exec hexstrike-ai nmap -sV 127.0.0.1`
- ✅ AI: Use Continue in VS Code