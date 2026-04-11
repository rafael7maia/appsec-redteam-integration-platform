# 🔧 Troubleshooting Guide

## **Common Issues**

### **Docker Container Issues**
```bash
# Container won't start
docker logs hexstrike-ai
docker restart hexstrike-ai

# Port already in use
docker stop hexstrike-ai
netstat -ano | findstr :8888
```

### **LM Studio Connection**
```bash
# Server not responding
curl http://localhost:1234/v1/models

# Check firewall
# Windows: Allow port 1234 in Windows Firewall
# Restart LM Studio server
```

### **Continue Extension**
- Reload VS Code window
- Check `.continue/config.json` syntax
- Verify LM Studio is running
- Test with simple prompt first

### **Nmap NSE Scripts**
```bash
# If nmap -sV fails, rebuild container:
docker build -t hexstrike-ai:v2 .
docker run -d --name hexstrike-ai -p 8888:8888 hexstrike-ai:v2
```

## **Health Check Commands**
```bash
# Full system check
docker ps
curl http://localhost:8888/health
curl http://localhost:1234/v1/models
docker exec hexstrike-ai nmap --version
```