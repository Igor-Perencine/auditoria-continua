"""Catálogo dos 93 controles do Anexo A da ISO/IEC 27001:2022 (títulos resumidos em português)
com a classificação de potencial de automação proposta no TCC (objetivo específico "a").

  A = automatizável  -> teste técnico completo, contínuo
  P = parcial        -> parte técnica automatizada + validação humana
  D = documental     -> verificação sobre políticas/documentos (RAG + auditor)
  M = manual         -> depende de inspeção física/entrevista
"""

AUTOMATION = {"A": "automatizavel", "P": "parcial", "D": "documental", "M": "manual"}

FREQUENCY = {
    "automatizavel": "Contínua (a cada ciclo de coleta)",
    "parcial": "Diária + revisão humana periódica",
    "documental": "Anual ou a cada nova versão de política",
    "manual": "Anual (auditoria presencial)",
}

THEMES = {"5": "Organizacional", "6": "Pessoas", "7": "Físico", "8": "Tecnológico"}

CONTROLS = [
    # 5 - Controles organizacionais (37)
    ("A.5.1", "Políticas de segurança da informação", "D"),
    ("A.5.2", "Papéis e responsabilidades pela segurança da informação", "D"),
    ("A.5.3", "Segregação de funções", "P"),
    ("A.5.4", "Responsabilidades da direção", "D"),
    ("A.5.5", "Contato com autoridades", "D"),
    ("A.5.6", "Contato com grupos de interesse especial", "D"),
    ("A.5.7", "Inteligência de ameaças", "P"),
    ("A.5.8", "Segurança da informação no gerenciamento de projetos", "D"),
    ("A.5.9", "Inventário de informações e outros ativos associados", "P"),
    ("A.5.10", "Uso aceitável de informações e outros ativos associados", "D"),
    ("A.5.11", "Devolução de ativos", "P"),
    ("A.5.12", "Classificação das informações", "P"),
    ("A.5.13", "Rotulagem de informações", "P"),
    ("A.5.14", "Transferência de informações", "D"),
    ("A.5.15", "Controle de acesso", "P"),
    ("A.5.16", "Gestão de identidade", "P"),
    ("A.5.17", "Informações de autenticação", "A"),
    ("A.5.18", "Direitos de acesso", "A"),
    ("A.5.19", "Segurança da informação nas relações com fornecedores", "D"),
    ("A.5.20", "Segurança da informação nos contratos com fornecedores", "D"),
    ("A.5.21", "Gestão da segurança da informação na cadeia de fornecimento de TIC", "D"),
    ("A.5.22", "Monitoramento, análise crítica e gestão de mudanças dos serviços de fornecedores", "D"),
    ("A.5.23", "Segurança da informação para uso de serviços em nuvem", "P"),
    ("A.5.24", "Planejamento e preparação da gestão de incidentes de segurança da informação", "D"),
    ("A.5.25", "Avaliação e decisão sobre eventos de segurança da informação", "P"),
    ("A.5.26", "Resposta a incidentes de segurança da informação", "P"),
    ("A.5.27", "Aprendizado com incidentes de segurança da informação", "D"),
    ("A.5.28", "Coleta de evidências", "P"),
    ("A.5.29", "Segurança da informação durante a disrupção", "D"),
    ("A.5.30", "Prontidão de TIC para a continuidade de negócios", "P"),
    ("A.5.31", "Requisitos legais, estatutários, regulamentares e contratuais", "D"),
    ("A.5.32", "Direitos de propriedade intelectual", "P"),
    ("A.5.33", "Proteção de registros", "P"),
    ("A.5.34", "Privacidade e proteção de dados pessoais", "D"),
    ("A.5.35", "Análise crítica independente da segurança da informação", "D"),
    ("A.5.36", "Conformidade com políticas, regras e normas de segurança da informação", "P"),
    ("A.5.37", "Documentação dos procedimentos de operação", "D"),
    # 6 - Controles de pessoas (8)
    ("A.6.1", "Seleção", "D"),
    ("A.6.2", "Termos e condições de contratação", "D"),
    ("A.6.3", "Conscientização, educação e treinamento em segurança da informação", "P"),
    ("A.6.4", "Processo disciplinar", "D"),
    ("A.6.5", "Responsabilidades após encerramento ou mudança da contratação", "P"),
    ("A.6.6", "Acordos de confidencialidade ou não divulgação", "D"),
    ("A.6.7", "Trabalho remoto", "P"),
    ("A.6.8", "Relato de eventos de segurança da informação", "D"),
    # 7 - Controles físicos (14)
    ("A.7.1", "Perímetros de segurança física", "M"),
    ("A.7.2", "Entrada física", "P"),
    ("A.7.3", "Segurança de escritórios, salas e instalações", "M"),
    ("A.7.4", "Monitoramento da segurança física", "P"),
    ("A.7.5", "Proteção contra ameaças físicas e ambientais", "M"),
    ("A.7.6", "Trabalho em áreas seguras", "M"),
    ("A.7.7", "Mesa limpa e tela limpa", "M"),
    ("A.7.8", "Localização e proteção de equipamentos", "M"),
    ("A.7.9", "Segurança de ativos fora das instalações", "M"),
    ("A.7.10", "Mídias de armazenamento", "P"),
    ("A.7.11", "Serviços de infraestrutura", "P"),
    ("A.7.12", "Segurança do cabeamento", "M"),
    ("A.7.13", "Manutenção de equipamentos", "P"),
    ("A.7.14", "Descarte seguro ou reutilização de equipamentos", "M"),
    # 8 - Controles tecnológicos (34)
    ("A.8.1", "Dispositivos endpoint do usuário", "A"),
    ("A.8.2", "Direitos de acesso privilegiado", "A"),
    ("A.8.3", "Restrição de acesso à informação", "P"),
    ("A.8.4", "Acesso ao código-fonte", "P"),
    ("A.8.5", "Autenticação segura", "A"),
    ("A.8.6", "Gestão de capacidade", "A"),
    ("A.8.7", "Proteção contra malware", "A"),
    ("A.8.8", "Gestão de vulnerabilidades técnicas", "A"),
    ("A.8.9", "Gestão de configuração", "A"),
    ("A.8.10", "Exclusão de informações", "P"),
    ("A.8.11", "Mascaramento de dados", "P"),
    ("A.8.12", "Prevenção de vazamento de dados", "P"),
    ("A.8.13", "Backup das informações", "A"),
    ("A.8.14", "Redundância dos recursos de processamento da informação", "P"),
    ("A.8.15", "Registro de logs", "A"),
    ("A.8.16", "Atividades de monitoramento", "A"),
    ("A.8.17", "Sincronização do relógio", "A"),
    ("A.8.18", "Uso de programas utilitários privilegiados", "P"),
    ("A.8.19", "Instalação de software em sistemas operacionais", "A"),
    ("A.8.20", "Segurança de redes", "P"),
    ("A.8.21", "Segurança dos serviços de rede", "P"),
    ("A.8.22", "Segregação de redes", "P"),
    ("A.8.23", "Filtragem da web", "A"),
    ("A.8.24", "Uso de criptografia", "P"),
    ("A.8.25", "Ciclo de vida de desenvolvimento seguro", "D"),
    ("A.8.26", "Requisitos de segurança da aplicação", "D"),
    ("A.8.27", "Princípios de arquitetura e engenharia de sistemas seguros", "D"),
    ("A.8.28", "Codificação segura", "P"),
    ("A.8.29", "Testes de segurança em desenvolvimento e aceitação", "P"),
    ("A.8.30", "Desenvolvimento terceirizado", "D"),
    ("A.8.31", "Separação dos ambientes de desenvolvimento, teste e produção", "P"),
    ("A.8.32", "Gestão de mudanças", "P"),
    ("A.8.33", "Informações de teste", "D"),
    ("A.8.34", "Proteção dos sistemas de informação durante os testes de auditoria", "D"),
]

assert len(CONTROLS) == 93, "O Anexo A da ISO/IEC 27001:2022 possui 93 controles"

# Palavras-chave para marcar automaticamente trechos de políticas com controles.
KEYWORDS = {
    "A.5.1": ["política de segurança da informação", "psi"],
    "A.5.2": ["papéis e responsabilidades", "responsabilidades"],
    "A.5.15": ["controle de acesso"],
    "A.5.16": ["identidade", "ciclo de vida de contas"],
    "A.5.17": ["senha", "autenticação"],
    "A.5.18": ["direitos de acesso", "revisão de acessos", "desligamento", "conta inativa", "contas inativas"],
    "A.5.30": ["continuidade"],
    "A.6.5": ["desligamento", "encerramento do contrato"],
    "A.7.7": ["mesa limpa", "tela limpa", "bloqueio de tela"],
    "A.8.2": ["privilegiad", "administrador"],
    "A.8.5": ["mfa", "multifator", "duplo fator"],
    "A.8.7": ["malware", "antivírus", "antimalware"],
    "A.8.8": ["vulnerabilidade", "patch", "atualização de segurança", "cve"],
    "A.8.9": ["baseline", "configuração segura", "hardening", "smbv1", "firewall"],
    "A.8.13": ["backup", "cópia de segurança", "restauração"],
    "A.8.15": ["log", "registro de eventos"],
    "A.8.16": ["monitoramento", "siem"],
    "A.8.17": ["ntp", "sincronização do relógio", "relógio"],
}
