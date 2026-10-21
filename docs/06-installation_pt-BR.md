# Instalando o pki-dash

> Traduções: [en](06-installation.md)

Cada release publica o mesmo programa de várias formas. Escolha a que serve à máquina.

| Você quer | Use | Plataformas |
|---|---|---|
| Um serviço num servidor Debian ou Ubuntu | o pacote `.deb` | linux amd64, arm64 |
| Um serviço no Fedora, RHEL, Rocky, Alma, openSUSE | o pacote `.rpm` | linux amd64, arm64 |
| Um container | a imagem `ghcr.io/marcioamatte/pki-dash` | linux amd64, arm64 |
| Qualquer outra coisa, ou só experimentar | o arquivo com o programa puro | linux, macOS, Windows; amd64, arm64 |

Os releases ficam na página **Releases** do repositório. Para uma CA de verdade, rode o pki-dash num servidor Linux: ele guarda as chaves cifradas das suas CAs, e os pacotes e a imagem preparam a conta, as permissões e o sandbox para isso. Os arquivos para macOS e Windows rodam o programa, sem um serviço em volta, e servem para experimentar.

## Confira o que você baixou

Cada release traz o `checksums.txt` e uma assinatura dele, `checksums.txt.sigstore.json`, feita pelo workflow de release com assinatura "keyless" do [Sigstore](https://www.sigstore.dev/): não existe chave privada em lugar nenhum que possa vazar, e a assinatura registra qual workflow de qual repositório a produziu. Instale o [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) e, com os arquivos numa mesma pasta:

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/marcioamatte/pki-dash/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Troque `v0.1.0` pela versão que você baixou. O primeiro comando prova que os checksums vêm do workflow de release deste projeto; o segundo prova que o seu arquivo é o que está listado. Os pacotes `.deb` e `.rpm` não são assinados com chaves GPG próprias: essa conferência é a garantia deles. O `dnf install ./arquivo.rpm` os aceita como estão; no zypper acrescente `--allow-unsigned-rpm`.

A imagem do container é assinada do mesmo jeito:

```bash
cosign verify ghcr.io/marcioamatte/pki-dash:0.1.0 \
  --certificate-identity "https://github.com/marcioamatte/pki-dash/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Cada arquivo tem um SBOM (a lista de tudo que há dentro dele, em SPDX) ao lado, como `*.sbom.json`, e a imagem traz o dela.

## Debian e Ubuntu

```bash
sudo apt install ./pki-dash_0.1.0_amd64.deb      # arm64 em servidores ARM
```

## Fedora, RHEL e família

```bash
sudo dnf install ./pki-dash_0.1.0_amd64.rpm      # arm64 em servidores ARM
```

## O que os pacotes preparam

- O programa, `/usr/bin/pki-dash`.
- Um **serviço systemd**, `pki-dash`, rodando com a conta própria `pki-dash` (sem login e sem home), com o sandbox ligado: só escreve no próprio diretório de dados, não enxerga arquivos nem dispositivos de outros usuários, não tem capabilities e tem limite de memória.
- As **configurações** em `/etc/pki-dash/pki-dash.env`. Suas edições nunca são sobrescritas por uma atualização.
- Os **dados** em `/var/lib/pki-dash`, legíveis só pelo serviço. O banco, com as chaves cifradas das CAs, fica ali.
- Um exemplo para entrar com o Keycloak, `/etc/pki-dash/oidc.env.example`.
- A documentação em `/usr/share/doc/pki-dash/`.

O serviço fica **instalado mas não iniciado**: o servidor se recusa a rodar até você escolher como ele é exposto.

### Primeira inicialização

1. Edite `/etc/pki-dash/pki-dash.env` e descomente **uma** das três formas de expor o serviço:
   - o seu certificado (`PKI_DASH_TLS_CERT` e `PKI_DASH_TLS_KEY`). A chave precisa ser legível pelo serviço: `sudo chgrp pki-dash /etc/pki-dash/tls.key && sudo chmod 640 /etc/pki-dash/tls.key`;
   - `PKI_DASH_TLS_SELF_SIGNED=true`, um certificado descartável para experimentar (os navegadores vão avisar);
   - `PKI_DASH_INSECURE_HTTP=true`, somente atrás de um proxy reverso que termina o TLS (veja [Implantação](02-deployment_pt-BR.md)).
2. `sudo systemctl enable --now pki-dash`
3. `sudo journalctl -u pki-dash | grep setup_token`: o token de uso único da primeira execução.
4. Abra o endereço no navegador, informe o token e crie o primeiro administrador e a senha mestra.

Se você deixar o passo 1 por fazer, o serviço para depois de algumas tentativas e o journal diz o que falta (`sudo journalctl -u pki-dash`).

### Configurações que você pode querer

Todas em `/etc/pki-dash/pki-dash.env`, depois `sudo systemctl restart pki-dash`:

- `PKI_DASH_LISTEN`: o endereço em que escutar (padrão `127.0.0.1:8443`, só esta máquina). Use o endereço do servidor para deixar outros entrarem. Abaixo da porta 1024 o serviço precisa de uma capability: veja o comentário no arquivo da unit.
- Atrás de um proxy: `PKI_DASH_TRUSTED_PROXIES`, veja [Implantação](02-deployment_pt-BR.md).
- Publicar CRLs: `PKI_DASH_PKI_LISTEN` e `PKI_DASH_PUBLIC_URL`, veja [Revogação](04-revocation_pt-BR.md).
- Todas as outras opções, e suas variáveis, estão em [Implantação](02-deployment_pt-BR.md).

### Entrando com o Keycloak (opcional)

Nada a fazer se você usa só contas locais: enquanto `/etc/pki-dash/oidc.env` não existir, não há SSO nem botão.

```bash
sudo cp /etc/pki-dash/oidc.env.example /etc/pki-dash/oidc.env
sudo $EDITOR /etc/pki-dash/oidc.env                  # emissor, client id, grupos
echo 'o-segredo-do-cliente' | sudo install -m 0640 -o root -g pki-dash /dev/stdin /etc/pki-dash/oidc-secret
sudo systemctl restart pki-dash
```

O arquivo explica cada linha, e [Entrando com Keycloak](05-sso-keycloak_pt-BR.md) cobre o que preparar do lado do Keycloak.

### Atualizando

Instale o pacote mais novo do mesmo jeito. Um serviço em execução é reiniciado, suas configurações e seus dados ficam, e o banco é atualizado no próprio início. **Faça backup antes** (veja [Implantação](02-deployment_pt-BR.md#backups)): o banco e a sua senha mestra são o que você não consegue recriar.

### Removendo

`sudo apt remove pki-dash` (ou `purge`, que também apaga as configurações) e `sudo dnf remove pki-dash` param e desativam o serviço. **Eles nunca apagam `/var/lib/pki-dash` nem a conta `pki-dash`**: ali estão as chaves das suas CAs e o log de auditoria. Apague o diretório você mesmo quando tiver certeza de que não vai precisar dele.

## Imagem de container

```bash
docker run -d --name pki-dash -p 8443:8443 -v pki-data:/data \
  ghcr.io/marcioamatte/pki-dash:0.1.0 -tls-self-signed
```

Troque `-tls-self-signed` pelas opções do seu certificado ([Implantação](02-deployment_pt-BR.md) tem um arquivo Compose com o endurecimento ligado). As tags são a versão exata (`0.1.0`), a linha menor (`0.1`) e `latest`; fixe a versão exata. Enquanto o pacote for privado, faça login no registro antes: `docker login ghcr.io` com um token do GitHub que possa ler pacotes.

## O programa puro

Baixe o arquivo do seu sistema, descompacte e rode:

```bash
tar xzf pki-dash_0.1.0_linux_amd64.tar.gz
./pki-dash -data-dir ./data -listen 127.0.0.1:8443 -tls-self-signed
```

No Windows, descompacte e rode `pki-dash.exe` com as mesmas opções. O arquivo Linux traz também o arquivo da unit e as configurações de exemplo em `packaging/`, para uma instalação manual sem os pacotes: crie uma conta `pki-dash`, copie os arquivos como os pacotes fazem e rode `systemctl enable --now pki-dash`.

## Fazendo um release (mantenedores)

1. Tudo integrado na `main`, CI verde. O pipeline roda no CI a cada mudança como **release (snapshot)**, construindo tudo isso sem publicar, para não falhar pela primeira vez no dia do release.
2. `git tag v0.1.0 && git push origin v0.1.0` (a tag é o que define um release; as versões seguem o [versionamento semântico](https://semver.org/lang/pt-BR/)).
3. O workflow **Release** repete as verificações e depois constrói os binários, arquivos, pacotes e a imagem, gera os SBOMs, assina os checksums e a imagem, envia a imagem ao `ghcr.io` e cria o release no GitHub com tudo isso e um changelog.
4. O pacote da imagem nasce **privado**. Para abri-lo: *Packages* do repositório → `pki-dash` → *Package settings* → *Change visibility*.
5. Teste um snapshot local com `make snapshot` (precisa do [GoReleaser](https://goreleaser.com/), versão em `.github/workflows/release.yml`, e do Docker).
