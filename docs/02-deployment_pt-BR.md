# Implantação

> Idioma principal: [English](02-deployment.md). Em caso de divergência, vale a versão em inglês.

O pki-dash é entregue como um único container: um binário estático com a interface web dentro, rodando como usuário sem privilégios, em um sistema de arquivos somente leitura, com um volume para os dados. Ele é voltado a homelabs e redes internas (veja o aviso no README).

## Início rápido com Docker Compose

```bash
mkdir certs
cp seu-servidor.crt certs/tls.crt && cp sua-chave.key certs/tls.key
# O container roda como o usuário 65532, então esse usuário precisa conseguir ler a chave:
docker run --rm -v "$PWD/certs:/certs" --user 0:0 busybox:stable \
  sh -c 'chown 65532:65532 /certs/tls.key && chmod 400 /certs/tls.key'
docker compose up -d --build
docker compose logs pki-dash | grep setup_token     # somente na primeira execução
```

Se o container reiniciar em loop com `permission denied` na chave, a causa é essa etapa de posse. (O `secrets:` do Compose não ajuda: fora do Swarm ele ignora o dono e o modo pedidos.)

Depois abra <https://localhost:8443>, informe o token de setup e crie o primeiro administrador e a **senha mestra**.

Ainda sem certificado? Para um teste rápido, troque o `command` no `docker-compose.yml` por `["-tls-self-signed"]`. O servidor cria um certificado descartável e o navegador vai avisar. Quando você tiver a sua CA aqui, use-a para emitir um certificado de verdade para o próprio pki-dash.

## Como o servidor é exposto

O servidor se recusa a iniciar até que você escolha, explicitamente, como ele é acessado:

| Opção | Uso |
|---|---|
| `-tls-cert ARQUIVO -tls-key ARQUIVO` | O seu certificado. A escolha normal. |
| `-tls-self-signed` | Um certificado descartável, para laboratório. |
| `-insecure-http` | HTTP puro: desenvolvimento local, ou atrás de um proxy reverso (veja abaixo). Sozinho, os cookies não recebem `Secure` e o HSTS fica desligado. |

## Atrás de um proxy reverso

Você pode colocar o pki-dash atrás de um proxy que termina o TLS (nginx, Traefik, Caddy, HAProxy...). Diga ao pki-dash em quais proxies acreditar:

```bash
pki-dash -insecure-http -listen 172.17.0.1:8080 -trusted-proxies 172.17.0.2
```

`-trusted-proxies` (`PKI_DASH_TRUSTED_PROXIES`) aceita endereços e faixas CIDR, separados por vírgula. O que muda:

- **O endereço do cliente** é lido de `X-Forwarded-For`, mas só em conexões que vêm de um proxy da lista, e lendo da direita: o primeiro endereço que não seja ele mesmo um proxy da lista. Entradas que o cliente colocou à esquerda do cabeçalho nunca são usadas, então ninguém escolhe o endereço sob o qual é limitado e registrado. Em qualquer outra conexão o cabeçalho é ignorado.
- **As sessões são sempre `Secure`** (com o nome de cookie `__Host-` e HSTS), porque o navegador fala https mesmo que o listener atrás do proxy não fale. Por isso o `-insecure-http` é o companheiro normal desta opção aqui: o listener em HTTP puro é só para o proxy, então associe-o a um endereço que só o proxy alcance.
- **A checagem de origem cruzada** compara o `Origin` do navegador com o host que o navegador usou, tomado de `X-Forwarded-Host` quando vem de um proxy da lista.
- Um proxy da lista que informa `X-Forwarded-Proto: http` recebe um erro explicativo, em vez de deixar o login falhar em silêncio.
- Uma faixa que confiaria em todos os endereços (`0.0.0.0/0`, `::/0`) é recusada na inicialização.

O proxy precisa enviar `X-Forwarded-For` (acrescentando, não substituindo: `$proxy_add_x_forwarded_for` no nginx), `X-Forwarded-Proto` e, se ele altera o cabeçalho `Host`, `X-Forwarded-Host`. Esta é a configuração do nginx com a qual foi testado:

```nginx
server {
    listen 8443 ssl;
    ssl_certificate     /etc/nginx/tls.crt;
    ssl_certificate_key /etc/nginx/tls.key;
    location / {
        proxy_pass http://172.17.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Traefik e Caddy acrescentam esses cabeçalhos sozinhos; confira se o seu faz o mesmo. Para o login com Keycloak, `-external-url` é o endereço do **proxy**, como o navegador o vê.

**Liste só o proxy em si, não as redes onde ficam seus usuários.** Se o endereço de um cliente cair dentro de uma faixa listada, esse cliente conta como proxy e os cabeçalhos forjados dele seriam aceitos. Um proxy na mesma máquina do navegador é a forma típica de errar isso num teste: `127.0.0.1` seria os dois ao mesmo tempo.

Variáveis de ambiente (as flags prevalecem): `PKI_DASH_DATA_DIR` (padrão `/data` na imagem), `PKI_DASH_LISTEN` (padrão `0.0.0.0:8443` na imagem), `PKI_DASH_TLS_CERT`, `PKI_DASH_TLS_KEY`, `PKI_DASH_TRUSTED_PROXIES`.

Para deixar as pessoas entrarem pelo Keycloak ou outro provedor OpenID Connect, veja [Entrando com Keycloak](05-sso-keycloak_pt-BR.md). Ele traz opções próprias (`-external-url`, `-oidc-*`).

## A senha mestra e os reinícios

As chaves privadas das CAs são criptografadas com a senha mestra e **nunca** são decifradas em disco. Após cada início o cofre fica bloqueado: entre como administrador e desbloqueie pela interface (ou `POST /api/v1/vault/unlock`) antes de emitir certificados. Não há recuperação se a senha for perdida.

## Backups

Todo o estado fica no volume de dados: o banco SQLite (usuários, CAs, chaves cifradas, certificados emitidos, log de auditoria). Faça o backup com o container parado, para que o banco e o seu log de escrita fiquem consistentes:

```bash
docker compose stop pki-dash
docker run --rm -v pki-dash_pki-data:/data -v "$PWD":/backup busybox:stable \
  tar czf /backup/pki-data-$(date +%F).tgz -C /data .
docker compose start pki-dash
```

Guarde o backup e a senha mestra **em lugares diferentes**: juntos, são tudo de que um atacante precisa. O nome do volume acima supõe o nome de projeto padrão do Compose; confira o seu com `docker volume ls`.

## Atualizando

```bash
git pull && docker compose up -d --build
```

O esquema é migrado no próprio início, e o servidor se recusa a abrir um banco gravado por uma versão mais nova que a dele.

## O que o container faz por você

- Roda como `65532:65532`, nunca como root; a imagem não tem shell nem gerenciador de pacotes.
- Sistema de arquivos raiz somente leitura, todas as capabilities do Linux removidas, `no-new-privileges`, limite de processos e de memória (o hash de senhas usa cerca de 64 MiB por login simultâneo, no máximo 4 por vez).
- O diretório de dados é `0700` e o arquivo do banco `0600`.
- Um health check (`pki-dash healthcheck`) para os orquestradores saberem quando ele está atendendo.
- As imagens base são fixadas por digest e atualizadas por pull requests do Dependabot.

## Limites que vale conhecer

- Uma única instância: sem cluster nem alta disponibilidade.
- O bloqueio de login é por conta, então quem conhece um usuário pode mantê-lo bloqueado; o limite de taxa por endereço é a mitigação.
- Publique a porta em uma única interface (o arquivo Compose usa `127.0.0.1`) e acesse por uma rede em que você confie.
