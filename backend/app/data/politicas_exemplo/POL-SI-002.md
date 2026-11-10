---
codigo: POL-SI-002
titulo: Política de Controle de Acesso e Autenticação
versao: 2.1
aprovada_em: 2026-02-18
controles: A.5.15, A.5.16, A.5.17, A.5.18, A.8.2, A.8.5
---
# Política de Controle de Acesso e Autenticação (documento fictício)

## 1. Princípios (A.5.15)
O acesso a sistemas é concedido pelo princípio do menor privilégio e da necessidade de conhecer. Toda conta é nominal e vinculada a um colaborador registrado no sistema de RH, exceto contas de serviço, que devem ter um responsável designado.

## 2. Ciclo de vida de contas (A.5.16 e A.5.18)
Contas de usuário sem logon há mais de 90 dias devem ser desabilitadas automaticamente. No desligamento de um colaborador, todos os seus acessos devem ser revogados em até 24 horas após a comunicação do RH. Os direitos de acesso são revisados trimestralmente pelos gestores.

## 3. Acesso privilegiado (A.8.2)
Somente as contas formalmente aprovadas pelo CISO podem pertencer a grupos administrativos. A lista vigente de contas privilegiadas aprovadas é: admin.ti (administração de infraestrutura) e svc.backup (conta de serviço do backup). Qualquer outra conta com privilégio administrativo constitui violação desta política.

## 4. Autenticação (A.5.17 e A.8.5)
Senhas devem ter no mínimo 12 caracteres, com complexidade habilitada, e a conta deve ser bloqueada após no máximo 10 tentativas inválidas. O uso de autenticação multifator (MFA) é obrigatório para todas as contas privilegiadas de pessoas. Contas de serviço são dispensadas de MFA desde que a senha seja gerenciada em cofre de senhas e trocada a cada 90 dias.
