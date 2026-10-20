# pki-dash

Um painel web para criar e gerenciar uma PKI interna (Root CA, CAs intermediárias e certificados de serviço), construído sobre o [cfssl](https://github.com/cloudflare/cfssl) da Cloudflare. Entregue como um único container.

> Idioma principal: [English](README.md)

> **Status: fase inicial de desenho. Nada utilizável ainda.**

> **Aviso:** o pki-dash é destinado a ambientes internos, como homelabs, laboratórios e máquinas de teste. **Não** é destinado a PKI pública nem a cenários em que o comprometimento da CA tenha impacto crítico. Não substitui HSM, cerimônia de chaves formal nem uma CA comercial.

## Objetivos

- Hierarquia Root → intermediária → certificado de serviço, com a Root mantida offline.
- UI amigável para emitir certificados e distribuir a confiança aos hosts.
- Security first: chaves das CAs cifradas em repouso, autenticação obrigatória, papéis multiusuário, auditoria e OIDC depois.

## Documentação

- [Visão e escopo](docs/00-vision-and-scope_pt-BR.md)
- [Decisão de stack](docs/01-stack-decision_pt-BR.md)

## Licença

[MIT](LICENSE). O software de terceiros incluído está listado em [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), incluindo o cfssl (BSD-2-Clause).
