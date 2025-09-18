#!/usr/bin/env python3
"""
Demo do Menu Interativo - AI AppSec + Red Team Platform v5.0
"""

def demo_interactive_menu():
    """Demonstra o menu interativo"""
    
    print("AI AppSec + Red Team Integration Platform v5.0 - Interactive Setup")
    print("=" * 70)
    
    # Simula escolhas do usuário
    print("\nSelecione o modo de operacao:")
    print("1. AppSec Only - Analise de codigo fonte (SCA, Secrets, SAST, DAST)")
    print("2. AppSec + Red Team - Analise completa com validacao externa")
    print("3. Red Team Only - Bug bounty hunting e pentest externo")
    print("\nEscolha (1-3): 2")  # Simula escolha
    
    print("\nNome do projeto: techcorp_demo")  # Simula entrada
    
    print("\n--- Configuracao Red Team ---")
    print("Target domain (ex: example.com): localhost:9000")  # Simula entrada
    
    print("\nTipo de negocio do target:")
    print("1. Entertainment (eventos, ingressos)")
    print("2. E-commerce (lojas online)")
    print("3. Financial (bancos, fintech)")
    print("4. Healthcare (sistemas medicos)")
    print("5. Government (setor publico)")
    print("\nEscolha (1-5): 2")  # Simula escolha
    
    print("\nTipo de autorizacao:")
    print("1. Bug Bounty Program (programa oficial)")
    print("2. Penetration Test (teste contratado)")
    print("3. Own System (sistema proprio)")
    print("4. Educational Lab (ambiente educacional)")
    print("\nEscolha (1-4): 4")  # Simula escolha
    
    # Gera config.env
    config = {
        'OPERATION_MODE': 'appsec_redteam',
        'PROJECT_NAME': 'techcorp_demo',
        'TARGET_DOMAIN': 'localhost:9000',
        'TARGET_PROFILE': 'e-commerce',
        'AUTHORIZATION': 'educational_lab'
    }
    
    with open('config.env', 'w') as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")
    
    print("\n" + "=" * 70)
    print("CONFIGURACAO SALVA")
    print("=" * 70)
    for key, value in config.items():
        print(f"{key}: {value}")
    
    print("\nconfig.env criado com sucesso!")
    print("Agora execute: python quick_start.py")

if __name__ == "__main__":
    demo_interactive_menu()