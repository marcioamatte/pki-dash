# Revogação e CRLs

> Idioma principal: [English](04-revocation.md). Em caso de divergência, vale a versão em inglês.

Você pode revogar um certificado de serviço (uma chave que vazou, um host desativado), e o pki-dash publica uma **CRL** (lista de certificados revogados) que os clientes podem usar para recusá-lo. O OCSP ainda não está implementado.

## O que ele faz

- **Revogar** um certificado na página de Certificados (ou `POST /api/v1/certificates/{id}/revoke`) com um motivo: `key_compromise`, `superseded`, `cessation_of_operation`, `affiliation_changed` ou `unspecified`. Admins e operadores podem revogar.
- A revogação é **definitiva**. Não existe "suspensão" nem volta: uma vez que os clientes guardaram em cache uma entrada da CRL, ela não pode ser desfeita, e fingir o contrário só criaria dúvida. Para voltar a ter um certificado funcionando, emita um novo.
- A **intermediária emissora assina a CRL**, com a chave que o serviço já guarda. Cada CA tem a sua lista.
- Uma CRL vale por **7 dias** e é reemitida **na hora a cada revogação**, **a cada 24 horas** e **quando o cofre é desbloqueado**. A janela de 7 dias faz com que um cofre bloqueado durante um fim de semana longo não leve os clientes a recusar tudo.
- A revogação é **registrada na hora, mesmo com o cofre bloqueado** (uma chave vazada precisa deixar de valer aqui imediatamente). Assinar a CRL exige a chave da CA, então nesse caso ela é publicada assim que você desbloqueia. Até lá o painel mostra a CRL como *atrasada*, e a API responde `crl_published: false`.

## Na interface web

Na página de **Certificados**:

- **Revogar**, ao lado de cada certificado (admins e operadores). Você escolhe um motivo e marca que não dá para desfazer. Se o cofre estiver bloqueado, o diálogo avisa que a revogação será registrada agora e publicada ao desbloquear.
- Certificados revogados aparecem riscados com o selo **Revogado** (passe o mouse para ver a data e o motivo). **Ocultar certificados revogados** tira esses da lista.
- **Listas de revogação** mostra, para cada intermediária, se a lista está *Em dia*, *Atrasada* (uma revogação foi registrada mas não publicada, normalmente porque o cofre está bloqueado), *Expirada* (clientes que checam vão recusar os certificados dela), *Ainda não publicada* ou *Não consegue publicar*. **Atualizar agora** reemite as listas; **Baixar CRL** entrega o PEM. Um aviso aparece para qualquer lista atrasada ou expirada. Depois de desbloquear o cofre, a página se atualiza sozinha.

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

## Revogando uma CA intermediária

Uma intermediária é revogada pela **Root dela**, e a Root fica offline. Por isso são duas metades: o painel registra a revogação e para de usar a CA na hora, e **você** traz de volta uma CRL que a Root assinou, que o painel então publica em nome da Root.

1. **Revogue** a intermediária (somente admins; `POST /api/v1/cas/{id}/revoke`, motivos como para certificados mais `ca_compromise`). A partir daí o serviço **se recusa a emitir** por ela e **não assina mais CRLs** com a chave dela. A revogação é definitiva. Os certificados que ela já emitiu não aparecem em lista nenhuma até a CRL da Root dizer que a própria CA foi revogada, e nesse momento os clientes rejeitam a cadeia inteira.
2. **Peça o que a CRL da Root precisa conter** (`GET /api/v1/cas/{root}/crl-request`): as intermediárias revogadas com seus números de série (hex e decimal) e o número a dar à CRL.
3. **Na máquina da Root, gere uma CRL completa** com qualquer uma das ferramentas (as duas foram testadas):

   **cfssl**: coloque as séries em decimal, uma por linha, em `serials.txt`:

   ```bash
   cfssl gencrl serials.txt root.pem root-key.pem 15552000 > root-crl.b64     # 15552000 s = 180 dias
   ```

   A saída é o base64 do DER, que o importador aceita como está. O cfssl não escreve número de CRL nem código de motivo, e data a lista até o segundo.

   **openssl**: precisa de um pequeno banco de CA. Uma linha por intermediária revogada em `index.txt` (separada por tabs; série em hex maiúsculo com número par de dígitos; datas como `YYMMDDHHMMSSZ`), o número em `crlnumber` e um `ca.cnf`:

   ```ini
   # index.txt  (campos separados por TAB)
   R	351021000000Z	261021025553Z,CACompromise	3BF66B5E5E2E0AD23554366822BEA765B04AA08E	unknown	/CN=Inter A

   # crlnumber
   01

   # ca.cnf
   [ca]
   default_ca = CA_default
   [CA_default]
   database = index.txt
   crlnumber = crlnumber
   certificate = root.pem
   private_key = root-key.pem
   default_md = sha384
   default_crl_days = 180
   ```

   ```bash
   openssl ca -config ca.cnf -gencrl -out root-crl.pem
   ```

   A lista do openssl leva o número da CRL e o motivo, então prefira-a se puder.
4. **Importe-a** (`POST /api/v1/cas/{root}/crl/import`, PEM, DER ou o base64 do cfssl). O painel a serve no `/crl/<id-da-root>.crl` da Root.

### Na interface web

- **Revogue** uma intermediária pela linha dela na página de Autoridades certificadoras (admins). Escolha um motivo (`ca_compromise` está disponível aqui) e confirme que é definitivo. O diálogo então oferece **Publicar a CRL da Root**.
- **CRL da Root**, na linha de uma Root (e **Publicar CRL da Root** no painel de *Listas de revogação*), abre um assistente: ele lista as intermediárias revogadas que a lista precisa conter, deixa você escolher a validade da lista e mostra os arquivos e o comando para **openssl** ou **cfssl**, já preenchidos (o número da CRL é o próximo). Execute-os na máquina da Root, depois cole ou escolha o resultado e clique em **Publicar CRL**.
- O painel de *Listas de revogação* também mostra a lista da Root: *Em dia*, *Atrasada* (não cita todas as intermediárias revogadas), *Aguardando a lista da Root* ou *Expirada*, com um aviso. Uma intermediária revogada aparece como *Aposentada*.
- Ao assinar uma nova intermediária, as receitas mostradas no painel agora incluem o endereço da CRL da Root, se o servidor tiver uma URL pública (veja acima).

### O que a importação confere

Ela é publicada em nome da Root, então é conferida antes:

- assinada pela **chave desta Root** e emitida pelo nome dela;
- uma lista **completa**: CRLs delta e parciais são recusadas;
- atual: não expirada, não datada no futuro;
- **mais nova que a já publicada**, para que uma lista antiga não possa ser recolocada e desfazer revogações em silêncio. Com número de CRL nos dois lados, o número precisa crescer; senão (cfssl), a data precisa ser estritamente posterior, o que uma máquina da Root com relógio errado pode atrapalhar: acerte o relógio e gere de novo;
- **consistente com este painel**: ela precisa listar toda intermediária revogada aqui, e nenhuma que não esteja (revogue-a aqui primeiro).

Uma recusa explica o motivo e não muda nada.

### Faça as intermediárias apontarem para a lista da Root

Os clientes só conseguem checar uma intermediária se o certificado dela disser onde está a CRL da Root. Inclua isso ao **assinar** uma intermediária (as receitas de [Mantendo a Root offline](03-offline-root_pt-BR.md) usam os mesmos arquivos):

```json
"crl_url": "http://pki.lab:8080/crl/<id-da-root>.crl",
"issuer_urls": ["http://pki.lab:8080/ca/<id-da-root>.crt"],
```
(no perfil do cfssl, ao lado de `usages`), ou no arquivo de extensões do openssl:

```ini
crlDistributionPoints = URI:http://pki.lab:8080/crl/<id-da-root>.crl
authorityInfoAccess = caIssuers;URI:http://pki.lab:8080/ca/<id-da-root>.crt
```

`<id-da-root>` é o id da Root, como nos endereços que o painel mostra. **Intermediárias assinadas antes disso não trazem esse endereço**: os clientes não conseguem descobrir a lista da Root para elas (assine-as de novo se quiser isso).

### A lista da Root também expira

Clientes rigorosos recusam uma cadeia cuja CRL expirou. Uma Root que quase nunca é ligada precisa, portanto, publicar uma lista com **validade longa** (os comandos acima usam 180 dias) e **renová-la antes de acabar**, mesmo sem mudança. O painel mostra a lista da Root como *Expirada* e avisa. Publique uma lista vazia assim que as intermediárias apontarem para a Root.

## Destruindo a chave de uma intermediária revogada

Uma intermediária revogada nunca mais vai assinar, então a chave privada dela é só um risco: é exatamente o que um atacante levaria. Depois que a revogação estiver publicada, destrua a chave.

Em **Autoridades certificadoras**, uma intermediária revogada cuja chave o painel ainda guarda oferece **Destruir chave**. Você digita o nome da CA e a senha mestra, como para a chave de uma Root, e a chave é apagada para sempre: não há cópia nem volta. Só para admin.

- **A CRL da Root precisa estar publicada antes.** O painel recusa até que a CRL da Root que lista essa intermediária tenha sido importada (veja acima): destruir a chave antes de os clientes poderem saber da revogação deixaria que continuassem confiando numa CA que só está aposentada do seu lado. A recusa explica isso e oferece abrir os passos da CRL da Root.
- **Só intermediária revogada.** Uma CA em boa situação mantém a chave; a ação não é oferecida para ela, e o servidor a recusa.
- **O que permanece:** o certificado da CA, a revogação e todos os certificados que ela emitiu continuam registrados e disponíveis para download, e a CRL da Root continua listando a CA. O que se vai é a capacidade de assinar qualquer coisa com essa CA, inclusive uma nova CRL dos certificados dela (que de toda forma deixa de ser renovada na revogação).
- O log de auditoria registra `ca.drop_key` com o número da CRL da Root que permitiu.

A chave de uma Root é outro caso: veja [Mantendo a Root offline](03-offline-root_pt-BR.md).

## Limites

- **Ainda sem OCSP.** Somente CRL.
- Uma Root não pode ser revogada: nada acima dela poderia assinar a declaração. Para aposentar uma, remova-a dos hosts que confiam nela.
- Uma CA só publica CRL se o certificado dela tiver o uso de chave **cRLSign**. As intermediárias feitas pelo pki-dash ou pelas receitas documentadas de cfssl/openssl têm. Se você importar uma sem ele, os certificados que ela emitir não trazem endereço de CRL (um aviso informa isso) e as revogações são registradas, mas não podem ser publicadas.
- Os clientes guardam a CRL em cache até ela expirar ou ser substituída, então a revogação chega a eles no próximo refresh, não instantaneamente.
