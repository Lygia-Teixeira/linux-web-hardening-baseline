# 03 — E-mail: TLS no SMTP, SPF, DKIM, DMARC e alertas do sistema

## MAIL-01 — TLS do Exim igual ao do Apache

- **Objetivo:** o SMTP (porta 25 com STARTTLS) só aceita TLS 1.2/1.3, impõe a ordem de cifras do servidor e não usa DHE. Ferramentas de avaliação testam o e-mail com os mesmos critérios do site, e o padrão do cPanel reprova.
- **Como aplicar:** [`templates/exim-tls.localopts.example`](../templates/exim-tls.localopts.example) (WHM → *Exim Configuration Manager → Advanced Editor*, ou `/etc/exim.conf.localopts` + `/scripts/buildeximconf`).
- **Como verificar:** `scripts/check-tls.sh --smtp <host-de-email> 25`; mensagens externas continuam entrando com `X=TLS` no `exim_mainlog`.
- **Mapeamento:** CIS 3.10 · NIST SC-8 · NIST SP 800-177 Rev. 1.

## MAIL-02 — SPF

- **Objetivo:** declarar quais servidores podem enviar pelo domínio.
- **Como aplicar:** um único TXT `v=spf1 +a +mx +ip4:<ip-do-servidor> ~all` (ou `-all`), mantendo `include:` de serviços que o domínio ainda usa. Exemplo em [`templates/dns-email-records.example.txt`](../templates/dns-email-records.example.txt).
- **Como verificar:** `dig +short TXT <dominio> | grep spf` (exatamente um resultado).
- **Mapeamento:** CIS 9.5 · NIST SP 800-177 Rev. 1.

## MAIL-03 — DKIM

- **Objetivo:** assinatura criptográfica das mensagens.
- **Como aplicar:** chave gerada no painel (cPanel → *Entregabilidade do e-mail*) e publicada em `default._domainkey.<dominio>`. Quando o DNS do domínio não é o do painel, o registro precisa ser criado no provedor de DNS.
- **Como verificar:** `dig +short TXT default._domainkey.<dominio>`; painel mostra DKIM válido.
- **Mapeamento:** CIS 9.5 · NIST SP 800-177 Rev. 1.

## MAIL-04 — DMARC com política efetiva

- **Objetivo:** instruir os destinatários a tratar mensagens não autenticadas e receber relatórios.
- **Como aplicar:** `_dmarc.<dominio>` com `v=DMARC1; p=quarantine; rua=mailto:<caixa-de-relatorios>`. `p=none` serve só para um período inicial de observação; avaliações de conformidade costumam reprovar `p=none`. `p=reject` quando todo envio legítimo estiver alinhado.
- **Atenção em migrações:** recriar SPF/DKIM/DMARC no DNS novo. É comum o DMARC existir no provedor antigo e sumir.
- **Como verificar:** `dig +short TXT _dmarc.<dominio>`.
- **Mapeamento:** CIS 9.5 (Implement DMARC) · NIST SP 800-177 Rev. 1.

## MAIL-05 — Alertas do próprio servidor

Um servidor cujo hostname está no domínio do provedor de VPS (sem controle de DNS) envia alertas **sem SPF/DKIM**. Grandes provedores de webmail rejeitam essas mensagens; com volume alto, a reputação do IP cai e **os e-mails dos clientes do servidor também deixam de ser entregues** (writeup 05 do repositório `incident-response-writeups`).

- **Opção preferida:** hostname em domínio próprio com A, PTR, SPF e DKIM.
- **Alternativa:** relay SMTP autenticado **só para remetentes do sistema** (router + transporte + autenticador próprios no Exim):
  - e-mails das contas continuam saindo direto, assinados com o DKIM delas;
  - credencial enviada só para o host do relay (`client_condition`);
  - arquivo de credencial `root:mail`, modo `640`, nunca versionado;
  - router desativado enquanto a credencial estiver vazia ou com placeholder;
  - conta de relay separada por servidor (cota diária e isolamento em caso de comprometimento).
- **Volume:** desligar alertas sem ação (no CSF, `PT_USERMEM/RSS/TIME`), manter os acionáveis.
- **Destino do root** no cPanel: `/etc/localaliases` (o que vale para o Exim), `/root/.forward` e o contato do servidor em `/etc/wwwacct.conf`.
- **Como verificar:** `exim -bt root` (rota esperada); `exim -bt <externo> -f <usuario-de-conta>` (o `-f` **antes** do destinatário; depois dele é ignorado) segue direto; `exim -bpc` estável; nenhuma resposta `5.7.26` recorrente.
- **Mapeamento:** NIST AU-5, SI-4 · CIS 8.11.

## Diagnóstico rápido

```bash
D=<dominio>; M=mail.$D
dig +short TXT $D | grep spf
dig +short TXT default._domainkey.$D | cut -c1-40
dig +short TXT _dmarc.$D
scripts/check-tls.sh --smtp $M 25
exim -bpc                                             # no servidor
grep -cE '5\.7\.26|Connection refused' /var/log/exim_mainlog
```

Ao diagnosticar recusa de conexão SMTP, testar com o usuário/grupo com que o Exim realmente entrega. Um usuário de teste bloqueado pelo `SMTP_BLOCK` do CSF dá `refused` por motivo local e leva a um diagnóstico errado.
