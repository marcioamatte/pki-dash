# pki-dash: Visão e Escopo (rascunho)

> Status: rascunho. Idioma principal: [English](00-vision-and-scope.md). Em caso de divergência, vale a versão em inglês.

## 1. O que é

Um painel web para criar e gerenciar uma PKI interna (Root CA, CAs intermediárias e certificados de serviço), usando o [cfssl](https://github.com/cloudflare/cfssl) da Cloudflare como motor criptográfico. Entregue como **um único container** (painel + cfssl) com um volume para os dados.

## 2. Público-alvo e aviso

Ambientes internos: homelabs, laboratórios, máquinas de teste e redes privadas.

**Disclaimer (deve aparecer no README e na UI):** o pki-dash não é destinado a PKI pública nem a ambientes onde o comprometimento da CA tenha impacto crítico. Não substitui HSM, cerimônia de chaves formal nem uma CA comercial.

## 3. Casos de uso do MVP

1. Criar uma Root CA.
2. Criar CAs intermediárias assinadas pela Root.
3. Exportar a chave da Root e removê-la do serviço, mantendo só o certificado público (a Root fica offline).
4. Importar uma intermediária assinada externamente.
5. Emitir certificados de serviço a partir de uma intermediária:
   - CN, SANs (DNS e IP), validade e perfil (server, client, ambos);
   - a partir de um CSR enviado (preferido) ou com chave gerada no servidor.
6. Baixar bundles: certificado, chave (quando gerada aqui) e cadeia completa.
7. Distribuição de confiança: baixar o certificado da Root (PEM/CRT) e ver snippets de instalação por sistema (Debian/Ubuntu, RHEL, Windows, macOS, Firefox).
8. Inventário: listar CAs e certificados, com validade e alertas de vencimento próximo.

## 4. Requisitos de segurança

Security first é um princípio do projeto: quando uma escolha troca segurança por conveniência, a segurança vence.

- **Chaves privadas das CAs criptografadas em repouso** com uma senha mestra definida na inicialização.
- **Autenticação obrigatória desde o dia 1.** Login local, admin criado no primeiro acesso.
- **Multiusuário com papéis** (ex.: admin, operador que emite certificados, leitor). Papéis exatos a definir.
- **Log de auditoria** de ações sensíveis (criação de CA, emissão, exportação de chave, login).
- **OIDC** (alvo inicial: Keycloak) como método de login adicional: implementado, veja [Entrando com Keycloak](05-sso-keycloak_pt-BR.md).

## 5. Modelo de ameaça (esboço)

| Ameaça | Mitigação prevista |
|---|---|
| Acesso indevido ao painel | Autenticação, papéis, auditoria |
| Roubo do volume de dados | Chaves das CAs criptografadas com senha mestra |
| Comprometimento da Root | Root removida do serviço após assinar intermediárias |
| Chave de serviço interceptada no download | Preferir fluxo por CSR; HTTPS no painel |
| Senha mestra perdida | Documentar que não há recuperação |

A refinar na próxima revisão.

## 6. Fora do escopo do MVP

- Revogação, CRL e OCSP (fase 2; exigem banco e um endpoint de CRL acessível pelos clientes).
- ACME e renovação automática.
- HSM / PKCS#11.
- Alta disponibilidade e múltiplas instâncias.
- Uso em PKI pública.

## 7. Decisões já tomadas

- Open source, com intenção de publicar no GitHub.
- Hierarquia: Root → Intermediárias → Certificados de serviço.
- Container único com cfssl embutido.
- Auth local no MVP, depois OIDC/Keycloak; multiusuário.
- **Idioma:** inglês é o idioma principal de código, documentação e UI. Traduções usam o sufixo `_pt-BR.*` (ex.: `README_pt-BR.md`); outros idiomas podem vir se surgirem contribuidores.
- **Licença:** MIT, mantida compatível com a BSD-2-Clause do cfssl. Ver seção 9.
- **Linguagem do backend:** Go é a direção preferida (não final até a revisão da stack).
- **Objetivos de UX:** telas amigáveis, conceitos simples, velocidade, performance, segurança e layout moderno. São metas, não restrições rígidas de tecnologia.

## 8. Em aberto

- Framework de frontend e armazenamento de dados.
- Integração com o cfssl: processo interno `cfssl serve` vs. uso como biblioteca.
- Papéis e permissões exatos.

## 9. Notas de licenciamento

O cfssl usa BSD-2-Clause, licença permissiva que permite redistribuição dentro de um projeto MIT. Condições a respeitar:

- Manter o aviso de copyright e o texto da licença do cfssl em tudo que redistribuirmos (fonte ou binário), por exemplo na imagem do container e em um arquivo `THIRD_PARTY_NOTICES`.
- Não sugerir endosso da Cloudflare nem usar o nome dela para divulgação.
- O cfssl e nossas outras dependências têm licenças próprias. Vamos auditá-las (verificação automática de licenças no CI) para garantir que nenhuma conflite com a distribuição MIT, e listá-las nos avisos.

Este é um resumo prático, não aconselhamento jurídico.
