# pki-dash

Um painel web para criar e gerenciar uma PKI interna (Root CA, CAs intermediárias e certificados de serviço), construído sobre o [cfssl](https://github.com/cloudflare/cfssl) da Cloudflare. Crie uma Root e mantenha-a offline, assine intermediárias e certificados de serviço, revogue-os e publique CRLs, com papéis, log de auditoria e login opcional com Keycloak. Instala-se como pacote `.deb`/`.rpm` com serviço systemd, como imagem de container ou como um único binário.

> Idioma principal: [English](README.md)

> **Status: pré-1.0 (v0.1.0).** Testado de ponta a ponta com cfssl, openssl, Keycloak e nginx reais, inclusive na infraestrutura do próprio autor, mas não auditado por mais ninguém. O comportamento pode mudar entre versões: leia as [notas de release](https://github.com/marcioamatte/pki-dash/releases) e faça backup antes de atualizar.

> **Aviso:** o pki-dash é destinado a ambientes internos, como homelabs, laboratórios e máquinas de teste. **Não** é destinado a PKI pública nem a cenários em que o comprometimento da CA tenha impacto crítico. Não substitui HSM, cerimônia de chaves formal nem uma CA comercial.

## Objetivos

- Hierarquia Root → intermediária → certificado de serviço, com a Root mantida offline.
- UI amigável para emitir certificados e distribuir a confiança aos hosts.
- Security first: chaves das CAs cifradas em repouso, autenticação obrigatória, papéis multiusuário, auditoria e login opcional com Keycloak/OIDC.

## Primeiros passos

Instale um release (recomendado): um pacote `.deb`/`.rpm` com serviço systemd, uma imagem de container, ou um binário puro para Linux, macOS e Windows. Veja [Instalação](docs/06-installation_pt-BR.md); os detalhes do Docker (um único container, sem privilégios, sistema de arquivos somente leitura) estão em [Implantação](docs/02-deployment_pt-BR.md).

Ou compile a partir do código:

```bash
make build                           # compila a interface web (requer Node 20.19+ ou 22.12+) e depois o binário Go em bin/
./bin/pki-dash -tls-self-signed      # ou -tls-cert/-tls-key, ou -insecure-http para desenvolvimento local
```

Depois abra <https://localhost:8443>.

O servidor se recusa a iniciar sem que você escolha como ele será servido. Na primeira execução ele imprime no log um **token de setup** de uso único; informe-o na interface web (ou envie a `POST /api/v1/setup`) para criar o primeiro admin e a senha mestra. Após cada reinício o vault fica bloqueado: desbloqueie pela interface (ou `POST /api/v1/vault/unlock`), para que as chaves das CAs nunca fiquem decifradas em disco.

## Documentação

- [Visão e escopo](docs/00-vision-and-scope_pt-BR.md)
- [Decisão de stack](docs/01-stack-decision_pt-BR.md)
- [Implantação (Docker)](docs/02-deployment_pt-BR.md)
- [Mantendo a Root offline](docs/03-offline-root_pt-BR.md)
- [Revogação e CRLs](docs/04-revocation_pt-BR.md)
- [Entrando com Keycloak (OIDC)](docs/05-sso-keycloak_pt-BR.md)
- [Instalação: pacotes, imagem, binários](docs/06-installation_pt-BR.md)

## Licença

[MIT](LICENSE). O software de terceiros incluído está listado em [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), incluindo o cfssl (BSD-2-Clause).
