# 04 — Decisões conscientes e exceções

Uma baseline honesta registra o que **não** foi adotado e por quê. Cada decisão abaixo tem contexto, motivo e o gatilho para revisitar.

## DNSSEC — não adotado

- **Contexto:** os domínios dos clientes são subdomínios de uma zona administrada por terceiros, e o DNS autoritativo deles está hospedado no painel de DNS do provedor de infraestrutura, sem servidor DNS próprio da operação.
- **Motivo:** a zona-pai **não é assinada**. Sem assinatura no pai não há registro DS publicado e a cadeia de confiança não fecha; assinar só a zona filha não traz proteção ao resolvedor.
- **Rever quando:** a zona-pai passar a ser assinada e a operação tiver DNS autoritativo que suporte DNSSEC com rotação de chaves.

## IPv6 — não adotado

- **Contexto:** os servidores não têm IPv6 configurado.
- **Motivo:** ativar IPv6 afeta todos os sites do servidor de uma vez (firewall, listas de bloqueio, logs, SPF, certificados, testes); exige um projeto próprio, não um ajuste de baseline.
- **Rever quando:** houver requisito de conformidade ou de acesso que exija IPv6. Registrar no plano de capacidade dos próximos servidores.

## OCSP stapling — não aplicável

- **Motivo:** a autoridade certificadora usada (Let's Encrypt) encerrou o serviço OCSP em 2025; os certificados não têm resposta OCSP para "grampear". Ferramentas de avaliação podem continuar reprovando o item: registrar como **não aplicável** no relatório.
- **Rever quando:** houver troca para uma AC que mantenha OCSP.

## HSTS sem `includeSubDomains` e sem `preload`

- **Motivo:** subdomínios de teste, administração ou legados nem sempre têm certificado válido; `includeSubDomains` os tornaria inacessíveis por um ano nos navegadores que já viram o cabeçalho. `preload` é praticamente irreversível.
- **Rever quando:** inventário de subdomínios concluído e todos com HTTPS válido.

## CSP começa em Report-Only

- **Motivo:** uma política errada quebra partes do site (vídeos, mapas, formulários, painel). Report-Only coleta as violações primeiro; o modo de bloqueio vem site a site.
- **Risco aceito:** enquanto estiver em Report-Only, a CSP não bloqueia nada e ferramentas de avaliação tendem a reprovar o item.

## 410 em vez de 403 no bloqueio de varreduras (quando o `lfd` bane por 403)

- **Motivo:** com `LF_APACHE_403` + ban permanente, cada robô que recebe 403 vira um ban; a lista de bans (de tamanho limitado) encheria de IPs de robôs e empurraria atacantes reais para fora. O 410 não gera "client denied" no `error_log`, que é o que o `lfd` conta.

## Não bloquear por IP quando o tráfego passa por CDN/proxy reverso

- **Motivo:** o IP visto é o do proxy; banir derruba todos os visitantes que passam por ele e não atinge o atacante. Usar regra de WAF (por padrão, domínio, caminho) e manter as faixas da CDN em `csf.ignore`.

## Não criar regra de WAF com log para tráfego legítimo ruidoso

- **Contexto:** um agente de inventário mal configurado de um cliente gerava milhares de requisições por dia a partir de um único NAT.
- **Motivo:** uma regra do WAF que **registra** o evento faria o IPS de host (`LF_MODSEC`) banir o NAT inteiro do cliente, derrubando o acesso dele a todos os sites. A solução foi recusar no Apache, sem log de WAF, e pedir ao cliente a correção do agente.

## cPHulk sem bloqueio no firewall

- **Motivo:** muitos usuários de um mesmo cliente saem por um único NAT. Bloqueio no firewall faria uma senha errada repetida derrubar os sites para toda a rede; bloqueando só o login, o impacto fica restrito ao painel.

## Controles cobrados por avaliações externas não citados em relatórios ao cliente

- Itens não adotados por decisão técnica (DNSSEC, IPv6) ficam registrados internamente com motivo. Itens não aplicáveis (OCSP) entram no relatório como "não aplicável", com justificativa.
