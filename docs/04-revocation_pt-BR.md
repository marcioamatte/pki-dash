# Revogação e CRLs

> Idioma principal: [English](04-revocation.md). Em caso de divergência, vale a versão em inglês.

Você pode revogar um certificado de serviço (uma chave que vazou, um host desativado), e o pki-dash publica uma **CRL** (lista de certificados revogados) que os clientes podem usar para recusá-lo. O OCSP ainda não está implementado.

## O que ele faz

- **Revogar** um certificado na página de Certificados (ou `POST /api/v1/certificates/{id}/revoke`) com um motivo: `key_compromise`, `superseded`, `cessation_of_operation`, `affiliation_changed` ou `unspecified`. Admins e operadores podem revogar.
- A revogação é **definitiva**. Não existe "suspensão" nem volta: uma vez que os clientes guardaram em cache uma entrada da CRL, ela não pode ser desfeita, e fingir o contrário só criaria dúvida. Para voltar a ter um certificado funcionando, emita um novo.
- A **intermediária emissora assina a CRL**, com a chave que o serviço já guarda. Cada CA tem a sua lista.
- Uma CRL vale por **7 dias** e é reemitida **na hora a cada revogação**, **a cada 24 horas** e **quando o cofre é desbloqueado**. A janela de 7 dias faz com que um cofre bloqueado durante um fim de semana longo não leve os clientes a recusar tudo.
- A revogação é **registrada na hora, mesmo com o cofre bloqueado** (uma chave vazada precisa deixar de valer aqui imediatamente). Assinar a CRL exige a chave da CA, então nesse caso ela é publicada assim que você desbloqueia. Até lá o painel mostra a CRL como *atrasada*, e a API responde `crl_published: false`.

## Publicação: o listener público

Os clientes baixam CRLs por HTTP puro, e um cliente que ainda não confia no TLS do próprio pki-dash precisa conseguir baixá-las. Por isso as CRLs são servidas por um **segundo listener, separado**, que não faz mais nada:

| URL | O quê |
|---|---|
| `GET /crl/<id-da-ca>.crl` | a última CRL da CA (DER, `application/pkix-crl`) |
| `GET /ca/<id-da-ca>.crt` | o certificado da CA (DER, `application/pkix-cert`) |

Sem API, sem login, sem cookies, sem caminho de escrita: só dados públicos, com suporte a `ETag`/`304` e limite de requisições por endereço. Todo o resto nessa porta é 404.

Habilite com duas configurações (flags ou variáveis de ambiente):

```bash
pki-dash ... -pki-listen 0.0.0.0:8080 -public-url http://pki.lab:8080
# PKI_DASH_PKI_LISTEN / PKI_DASH_PUBLIC_URL
```

`-public-url` é como **os seus clientes** chegam a esse listener, e ele é escrito em todo certificado emitido a partir daí (as extensões *CRL Distribution Points* e *Authority Information Access*). Escolha um nome estável. Com a imagem Docker, publique também a porta 8080 (veja o arquivo Compose).

> **Certificados emitidos antes de você definir `-public-url` não trazem endereço**, então os clientes não têm onde buscar a CRL deles. Reemita-os se precisar que sejam verificados.

## Conferindo

```bash
# o certificado diz onde procurar
openssl x509 -in leaf.pem -noout -ext crlDistributionPoints,authorityInfoAccess

# o openssl verifica contra a CRL e recusa um certificado revogado:
curl -s http://pki.lab:8080/crl/<id-da-ca>.crl | openssl crl -inform DER -out crl.pem
openssl verify -CAfile root.pem -untrusted intermediate.pem -crl_check -CRLfile crl.pem leaf.pem
#  -> error 23 at 0 depth lookup: certificate revoked
```

## Quem de fato consulta uma CRL

Seja realista sobre isso. **Navegadores, em geral, não baixam CRLs de CAs privadas.** A revogação vale onde algo que *você controla* a consulta:

- servidores que validam **certificados de cliente** (TLS mútuo): nginx `ssl_crl`, HAProxy `crl-file`, Envoy, Traefik e similares;
- ferramentas e bibliotecas que você configura para checar revogação (`openssl verify -crl_check`, Java, Go com verificador próprio, `curl --crlfile`);
- qualquer coisa que busque a lista por conta própria.

Use para mTLS e para serviços que você opera. Não espere que ela faça um certificado de servidor revogado sumir de todos os navegadores.

## Limites

- **Ainda sem OCSP.** Somente CRL.
- **Intermediárias ainda não podem ser revogadas.** Essa lista precisa ser assinada pela Root, que fica offline; isso vem na próxima mudança.
- Uma CA só publica CRL se o certificado dela tiver o uso de chave **cRLSign**. As intermediárias feitas pelo pki-dash ou pelas receitas documentadas de cfssl/openssl têm. Se você importar uma sem ele, os certificados que ela emitir não trazem endereço de CRL (um aviso informa isso) e as revogações são registradas, mas não podem ser publicadas.
- Os clientes guardam a CRL em cache até ela expirar ou ser substituída, então a revogação chega a eles no próximo refresh, não instantaneamente.
