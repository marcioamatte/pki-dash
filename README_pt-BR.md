# pki-dash

Um painel web para criar e gerenciar uma PKI interna (Root CA, CAs intermediárias e certificados de serviço), construído sobre o [cfssl](https://github.com/cloudflare/cfssl) da Cloudflare. Entregue como um único container.

> Idioma principal: [English](README.md)

> **Status: desenvolvimento inicial. O backend, a API JSON e uma primeira interface web (setup, login, desbloqueio do cofre, criar e listar CAs) funcionam. Faltam as telas de emissão de certificados e de gestão de usuários. Não está pronto para uso real.**

> **Aviso:** o pki-dash é destinado a ambientes internos, como homelabs, laboratórios e máquinas de teste. **Não** é destinado a PKI pública nem a cenários em que o comprometimento da CA tenha impacto crítico. Não substitui HSM, cerimônia de chaves formal nem uma CA comercial.

## Objetivos

- Hierarquia Root → intermediária → certificado de serviço, com a Root mantida offline.
- UI amigável para emitir certificados e distribuir a confiança aos hosts.
- Security first: chaves das CAs cifradas em repouso, autenticação obrigatória, papéis multiusuário, auditoria e OIDC depois.

## Executando (desenvolvimento)

```bash
make build                           # compila a interface web (requer Node 20.19+ ou 22.12+) e depois o binário Go em bin/
./bin/pki-dash -tls-self-signed      # ou -tls-cert/-tls-key, ou -insecure-http para desenvolvimento local
```

Depois abra <https://localhost:8443>.

O servidor se recusa a iniciar sem que você escolha como ele será servido. Na primeira execução ele imprime no log um **token de setup** de uso único; informe-o na interface web (ou envie a `POST /api/v1/setup`) para criar o primeiro admin e a senha mestra. Após cada reinício o vault fica bloqueado: desbloqueie pela interface (ou `POST /api/v1/vault/unlock`), para que as chaves das CAs nunca fiquem decifradas em disco.

## Documentação

- [Visão e escopo](docs/00-vision-and-scope_pt-BR.md)
- [Decisão de stack](docs/01-stack-decision_pt-BR.md)

## Licença

[MIT](LICENSE). O software de terceiros incluído está listado em [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), incluindo o cfssl (BSD-2-Clause).
