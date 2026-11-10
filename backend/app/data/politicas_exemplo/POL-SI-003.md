---
codigo: POL-SI-003
titulo: Norma de Operações de TI e Gestão de Vulnerabilidades
versao: 1.4
aprovada_em: 2026-04-02
controles: A.8.7, A.8.8, A.8.9, A.8.15, A.8.17
---
# Norma de Operações de TI e Gestão de Vulnerabilidades (documento fictício)

## 1. Proteção contra malware (A.8.7)
Todos os servidores e estações devem manter a solução antimalware ativa, com assinaturas atualizadas há no máximo 3 dias.

## 2. Gestão de vulnerabilidades e atualizações (A.8.8)
Vulnerabilidades críticas (CVSS maior ou igual a 9,0) devem ser corrigidas em até 15 dias; vulnerabilidades altas (CVSS entre 7,0 e 8,9) em até 30 dias. Os sistemas operacionais devem receber atualizações de segurança em no máximo 45 dias.

## 3. Configuração segura — baseline (A.8.9)
O baseline aprovado exige: firewall de host ativo, protocolo SMBv1 desabilitado e acesso RDP somente com NLA (Network Level Authentication).

## 4. Exceções vigentes ao baseline
Exceção EXC-2026-003: o servidor SRV-LEGADO01, que executa o sistema legado de folha de pagamento, está autorizado a manter o protocolo SMBv1 habilitado até 31/03/2027, prazo previsto para a migração do sistema. A exceção foi aprovada pelo CISO em 15/01/2026, com controles compensatórios: servidor isolado em VLAN dedicada, acesso SMB restrito por firewall de rede apenas ao servidor de aplicação e monitoramento reforçado no SIEM.

## 5. Registro de eventos (A.8.15)
Todos os ativos devem enviar logs ao SIEM. Uma fonte sem eventos por mais de 60 minutos deve ser tratada como incidente de monitoramento.

## 6. Sincronização de relógios (A.8.17)
Todos os ativos devem sincronizar o relógio com os servidores NTP corporativos, com desvio máximo tolerado de 60 segundos, para garantir a correlação de eventos.
