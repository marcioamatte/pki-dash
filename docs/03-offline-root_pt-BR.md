# Mantendo a Root offline

> Idioma principal: [English](03-offline-root.md). Em caso de divergência, vale a versão em inglês.

A Root é a âncora de confiança de tudo abaixo dela, então o lugar mais seguro para a chave privada dela é uma máquina que não esteja em rede. O pki-dash suporta isso de duas formas, e as duas terminam igual: o serviço guarda a chave da intermediária e emite certificados, mas nunca tem a da Root.

## Qual caminho?

| Sua situação | O que fazer |
|---|---|
| A Root foi feita **em outro lugar** (cfssl, openssl, outra máquina) | [Importe o certificado público dela](#uma-root-feita-em-outro-lugar) e depois peça uma intermediária. |
| Você criou a Root **no pki-dash** | Use **Deixar offline** na Root (exporte a chave e depois remova-a do serviço) e depois peça uma intermediária. |

## Uma Root feita em outro lugar

1. **Importe a Root.** Envie só o certificado público (`POST /api/v1/cas/import-root`). O serviço confere que ele é autoassinado, de uma CA que pode ter intermediárias (path length diferente de 0), com chave forte e válido agora. A chave privada nunca é enviada nem é necessária.
2. **Peça uma intermediária** (`POST /api/v1/cas/{root}/intermediate-requests`). O pki-dash gera a chave da intermediária e a guarda, cifrada com a senha mestra, e devolve uma requisição de certificado (CSR). A chave nunca sai do serviço.
3. **Assine o CSR na máquina que guarda a Root.** Duas formas, ambas testadas:

   **cfssl**, com um perfil que cria uma CA que só assina certificados de serviço (`ca-config.json`):

   ```json
   {
     "signing": {
       "profiles": {
         "intermediate": {
           "usages": ["cert sign", "crl sign"],
           "expiry": "17520h",
           "ca_constraint": { "is_ca": true, "max_path_len": 0, "max_path_len_zero": true }
         }
       }
     }
   }
   ```

   ```bash
   cfssl sign -ca root.pem -ca-key root-key.pem -config ca-config.json -profile intermediate inter.csr \
     | cfssljson -bare inter          # gera inter.pem
   ```

   **openssl**, com um arquivo de extensões (`inter.ext`):

   ```ini
   basicConstraints = critical, CA:TRUE, pathlen:0
   keyUsage = critical, keyCertSign, cRLSign
   subjectKeyIdentifier = hash
   authorityKeyIdentifier = keyid
   ```

   ```bash
   openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial \
     -days 730 -sha384 -extfile inter.ext -out inter.crt
   ```

   > **Revogação:** se você quer que os clientes possam checar a intermediária contra a CRL da Root depois, inclua o endereço dela agora (`crl_url` e `issuer_urls` no perfil do cfssl, ou `crlDistributionPoints` e `authorityInfoAccess` nas extensões do openssl). Veja [Revogando uma CA intermediária](04-revocation_pt-BR.md#revogando-uma-ca-intermediária).

4. **Importe o certificado assinado** (`POST /api/v1/intermediate-requests/{id}/import`). A partir daí a intermediária se comporta como qualquer outra: emite certificados de serviço, e eles verificam contra a Root que você nunca deu ao serviço.

## Na interface web

Tudo o que está acima é uma tela, então raramente você precisa da API diretamente:

1. **Importar Root** (na página de Autoridades certificadoras): cole o certificado público da Root ou escolha o arquivo `.crt` / `.pem`.
2. **Nova CA**, tipo *Intermediária*, pai = essa Root. Uma Root cuja chave não está com o serviço é oferecida como pai e o formulário passa para **Criar requisição**. (Para uma Root cuja chave *está* com o serviço, marque *Assinar em outro lugar* para fazer o mesmo.) Você recebe o CSR para baixar e os comandos exatos para cfssl ou openssl, com a validade limitada para que a intermediária termine antes da Root.
3. Assine na máquina da Root com esses comandos.
4. Em **Aguardando certificado assinado**, escolha **Importar certificado** e cole ou escolha o arquivo assinado. Uma recusa explica o que está errado (por exemplo "uma intermediária precisa ter path length 0") e mantém o pedido, então você pode corrigir o arquivo e tentar de novo. **Como assinar** reabre os comandos; **Cancelar pedido** descarta o pedido e a chave dele.

## O que a importação confere

Um certificado só é aceito se tudo isto valer, então um engano (ou um arquivo adulterado) não passa:

- ele é **para a chave que fez a requisição**, não para outra;
- ele é **assinado pela Root** que você escolheu;
- ele é uma **CA com path length 0**: pode assinar certificados de serviço e nada além. Um certificado sem `pathlen` (o padrão do openssl quando você esquece) é **recusado**, com explicação;
- o uso da chave permite assinar certificados;
- ele é válido agora e **dentro da validade da própria Root**.

Uma importação recusada deixa a requisição no lugar, então você pode corrigir o certificado e tentar de novo, ou cancelar a requisição, o que descarta a chave dela.

## Sempre limite para quais nomes uma intermediária pode emitir

**Faça isso em toda intermediária.** Se a chave dela vazar, uma intermediária sem restrição pode se passar por qualquer nome de host; uma com restrição só pelos seus domínios. O painel avisa quando a lista está vazia, e o [guia de segurança](07-security-guidance_pt-BR.md) explica por que esse é o limite mais útil que você pode definir.

Nas instruções de assinatura você pode listar **domínios** (por exemplo `lab, mattegroup.example`). A receita do openssl então inclui na intermediária uma extensão `nameConstraints` crítica: todo cliente que valida a cadeia rejeita um certificado para qualquer outro nome, mesmo que a chave da intermediária vaze. Um domínio vale para ele mesmo e tudo abaixo dele.

- **Só a receita do openssl consegue.** A linha de comando do cfssl não tem como incluir a extensão; com domínios listados, a aba do cfssl avisa isso em vez de mostrar uma receita que os deixaria de fora em silêncio.
- O serviço lê as restrições do certificado importado e **recusa emitir** para nomes fora delas (nomes DNS e faixas de IP), em vez de produzir um certificado que nenhum cliente aceitaria.
- Coloque as restrições na intermediária, não na Root, para limitar uma intermediária sem mexer nas outras.
- Uma intermediária **criada dentro do pki-dash** sob uma Root que o serviço guarda **não pode** ter restrição (o cfssl não consegue incluir a extensão). As restrições são mais um motivo para manter a Root offline.
- Só os **nomes DNS** são limitados; os endereços IP não são.

## Quem alcança a Root

A máquina da Root, a chave e a senha dela são o que há de mais valioso na sua PKI, e tudo o que está acima acontece fora do painel. Mantenha pequeno o círculo de pessoas que as alcançam, mantenha a chave e a senha separadas e **registre você mesmo cada assinatura**: veja [Protegendo a sua PKI, seção 5](07-security-guidance_pt-BR.md#5-limite-quem-alcança-a-root-offline-e-registre-cada-assinatura).

## Observações

- A validade da Root precisa ultrapassar a da intermediária. Escolha `-days` / `expiry` de acordo.
- As requisições pendentes guardam as chaves cifradas como qualquer outra, e uma troca da senha mestra as leva junto.
- Cada passo fica no log de auditoria: `ca.import_root`, `ca.request_intermediate`, `ca.import_intermediate`, `ca.request_cancel`.
