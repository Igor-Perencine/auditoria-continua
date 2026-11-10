---
codigo: POL-SI-004
titulo: Política de Backup e Continuidade
versao: 2.0
aprovada_em: 2025-12-05
controles: A.8.13, A.8.14, A.5.30
---
# Política de Backup e Continuidade (documento fictício)

## 1. Backup das informações (A.8.13)
Os servidores DC01, SRV-DB01 e SRV-WEB01 devem ter backup completo diário. Deve existir backup bem-sucedido nas últimas 26 horas (24 horas mais tolerância de janela de execução). A retenção mínima é de 30 dias.

## 2. Testes de restauração
O sucesso do job de backup não comprova a recuperabilidade. Devem ser realizados testes de restauração ao menos a cada 90 dias para cada servidor crítico, com registro do resultado.

## 3. Continuidade (A.5.30 e A.8.14)
Os serviços críticos devem possuir plano de recuperação com RTO de 8 horas e RPO de 24 horas, testado anualmente.
