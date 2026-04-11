# 📁 Projetos - Estrutura Organizacional

## 🎯 **Propósito**

Esta pasta contém todos os artefatos e resultados de projetos de segurança organizados por cliente/empresa.

## 🏗️ **Estrutura**

```
projetos/
├── cliente1/                    # Nome da empresa/cliente
│   ├── scan_results.json       # Resultados do core_scanner
│   ├── evidencias/             # Screenshots, logs, provas
│   ├── relatorios/             # Relatórios finais
│   └── configuracao.env        # Config específica do projeto
├── cliente2/
│   └── ...
└── README.md                   # Este arquivo
```

## 📋 **Convenções**

### **Nomenclatura de Pastas:**
- Use o nome da empresa/cliente em minúsculas
- Substitua espaços por underscores: `empresa_exemplo`
- Para projetos internos use: `interno_teste_YYYYMMDD`

### **Arquivos Obrigatórios por Projeto:**
- `config.env` - Configuração do target
- `{domain}_scan_results_v5.json` - Resultados do scan
- `evidencias/` - Pasta com provas técnicas
- `relatorios/` - Pasta com relatórios finais

## 🚀 **Como Usar**

### **1. Criar Novo Projeto:**
```bash
# Criar pasta do cliente
mkdir projetos/nova_empresa

# Configurar target
echo "TARGET_DOMAIN=empresa.com" > projetos/nova_empresa/config.env
echo "TARGET_PROFILE=e-commerce" >> projetos/nova_empresa/config.env
echo "AUTHORIZATION=penetration_test" >> projetos/nova_empresa/config.env
```

### **2. Executar Scan:**
```bash
# Copiar config para raiz temporariamente
cp projetos/nova_empresa/config.env .

# Executar scan
python quick_start.py

# Mover resultados para pasta do projeto
mv empresa.com_scan_results_v5.json projetos/nova_empresa/
```

### **3. Organizar Evidências:**
```bash
# Criar estrutura de evidências
mkdir projetos/nova_empresa/evidencias
mkdir projetos/nova_empresa/relatorios

# Mover evidências coletadas
mv screenshots/ projetos/nova_empresa/evidencias/
mv logs/ projetos/nova_empresa/evidencias/
```

## 📊 **Projetos Existentes**

### **ingresso/ - Caso de Estudo**
- **Cliente**: Ingresso.com (Bug Bounty)
- **Tipo**: Teste de validação da plataforma v5.0
- **Status**: Concluído - Zero vulnerabilidades reais
- **Resultado**: 100% accuracy, eliminação de falsos positivos

## ⚖️ **Política de Retenção**

- **Projetos ativos**: Mantidos indefinidamente
- **Projetos concluídos**: Arquivar após 1 ano
- **Dados sensíveis**: Remover após entrega do relatório
- **Evidências**: Manter apenas o necessário para auditoria

## 🔒 **Segurança**

- **Nunca commitar** dados sensíveis reais
- **Usar placeholders** em exemplos públicos
- **Criptografar** evidências confidenciais
- **Seguir LGPD** para dados pessoais

---

**📁 Estrutura organizacional para projetos profissionais de segurança**