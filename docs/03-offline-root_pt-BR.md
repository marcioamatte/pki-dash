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
           "expiry": "43800h",
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
     -days 1825 -sha384 -extfile inter.ext -out inter.crt
   ```

4. **Importe o certificado assinado** (`POST /api/v1/intermediate-requests/{id}/import`). A partir daí a intermediária se comporta como qualquer outra: emite certificados de serviço, e eles verificam contra a Root que você nunca deu ao serviço.

## O que a importação confere

Um certificado só é aceito se tudo isto valer, então um engano (ou um arquivo adulterado) não passa:

- ele é **para a chave que fez a requisição**, não para outra;
- ele é **assinado pela Root** que você escolheu;
- ele é uma **CA com path length 0**: pode assinar certificados de serviço e nada além. Um certificado sem `pathlen` (o padrão do openssl quando você esquece) é **recusado**, com explicação;
- o uso da chave permite assinar certificados;
- ele é válido agora e **dentro da validade da própria Root**.

Uma importação recusada deixa a requisição no lugar, então você pode corrigir o certificado e tentar de novo, ou cancelar a requisição, o que descarta a chave dela.

## Observações

- A validade da Root precisa ultrapassar a da intermediária. Escolha `-days` / `expiry` de acordo.
- As requisições pendentes guardam as chaves cifradas como qualquer outra, e uma troca da senha mestra as leva junto.
- Cada passo fica no log de auditoria: `ca.import_root`, `ca.request_intermediate`, `ca.import_intermediate`, `ca.request_cancel`.
