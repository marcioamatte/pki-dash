# Entrando com Keycloak (OpenID Connect)

> Traduções: [en](05-sso-keycloak.md)

O pki-dash pode deixar as pessoas entrarem por um provedor de identidade que fale OpenID Connect. Este guia usa o **Keycloak**, mas qualquer provedor que ofereça o fluxo padrão de código de autorização e coloque uma claim de grupos no ID token funciona do mesmo jeito.

## O que você ganha

- Um botão **Entrar com Keycloak** na tela de login. As contas locais continuam funcionando ao lado dele.
- **Os papéis vêm dos grupos.** Você decide qual grupo do Keycloak significa admin, operador ou visualizador; o papel é recalculado a cada login, então o provedor continua sendo a fonte da verdade.
- **Nada é concedido por padrão.** Quem não está em nenhum dos grupos mapeados não consegue entrar (a menos que você defina um papel padrão) e nenhuma conta é criada para essa pessoa.
- As contas são criadas no primeiro login e aparecem em **Usuários** marcadas como OIDC.

O administrador local que você cria na primeira execução continua existindo. Mantenha-o: é por ele que você entra se o provedor estiver fora do ar ou mal configurado.

## 1. Preparar o Keycloak

Passos para o console de administração do Keycloak 26. Os nomes podem variar um pouco em outras versões.

1. **Grupos.** No seu realm, vá em *Groups* e crie `pki-admins`, `pki-operators` e `pki-viewers` (ou os nomes que preferir; você os informa ao pki-dash abaixo).
2. **Cliente.** *Clients → Create client*:
   - Client type **OpenID Connect**, Client ID `pki-dash`.
   - Capability config: **Client authentication: On**; marque apenas **Standard flow** (desligue *Direct access grants*).
   - Access settings: *Root URL* `https://pki.lab:8443`, *Valid redirect URIs* exatamente `https://pki.lab:8443/api/v1/auth/oidc/callback`. Deixe *Web origins* vazio. Use o endereço que os navegadores usam para chegar ao pki-dash.
3. **Exigir PKCE.** No cliente, *Advanced → Advanced settings*, defina **Proof Key for Code Exchange Code Challenge Method** como `S256` e salve. O pki-dash sempre envia PKCE; isso faz o Keycloak exigi-lo.
4. **Segredo.** Aba *Credentials*: copie o **Client secret**.
5. **Grupos no ID token.** *Clients → pki-dash → Client scopes → pki-dash-dedicated → Configure a new mapper → Group Membership*:
   - Name `groups`, Token Claim Name `groups`.
   - **Add to ID token: On**. Add to access token e userinfo podem ficar desligados.
   - *Full group path* pode ficar ligado ou desligado: o pki-dash aceita `/pki-admins` e `pki-admins` igualmente.
6. **Usuários.** Coloque as pessoas nos grupos: *Users → o usuário → Groups → Join group*.

## 2. Rodar o pki-dash com ele

Guarde o segredo do cliente em um arquivo que só o serviço consiga ler e passe as configurações:

```bash
printf '%s\n' 'o-segredo-do-cliente' > secrets/oidc-secret && chmod 400 secrets/oidc-secret

pki-dash -tls-cert tls.crt -tls-key tls.key \
  -external-url https://pki.lab:8443 \
  -oidc-issuer https://keycloak.lab/realms/lab \
  -oidc-client-id pki-dash \
  -oidc-client-secret-file secrets/oidc-secret \
  -oidc-name Keycloak \
  -oidc-admin-groups pki-admins \
  -oidc-operator-groups pki-operators \
  -oidc-viewer-groups pki-viewers
```

No container, monte o segredo (e o seu pacote de CA, veja abaixo) somente para leitura e passe as mesmas opções no `command` do Compose; o `docker-compose.yml` tem as linhas prontas para descomentar.

| Opção (variável de ambiente) | Significado |
|---|---|
| `-oidc-issuer` (`PKI_DASH_OIDC_ISSUER`) | A URL do emissor do realm, `https://HOST/realms/NOME`. Defini-la liga o SSO. |
| `-oidc-client-id` (`PKI_DASH_OIDC_CLIENT_ID`) | O ID do cliente no provedor. |
| `-oidc-client-secret-file` (`PKI_DASH_OIDC_CLIENT_SECRET_FILE`) | Arquivo com o segredo do cliente. `PKI_DASH_OIDC_CLIENT_SECRET` também funciona; de propósito não existe flag com o segredo, porque a linha de comando é visível a outros usuários. Sem segredo nenhum, o cliente é público (só PKCE). |
| `-external-url` (`PKI_DASH_EXTERNAL_URL`) | Como os navegadores chegam ao pki-dash, só esquema e host, por exemplo `https://pki.lab:8443`. O endereço de retorno é montado a partir dele e precisa bater com o que você registrou. |
| `-oidc-name` (`PKI_DASH_OIDC_NAME`) | Texto do botão. Padrão `SSO`. |
| `-oidc-admin-groups`, `-oidc-operator-groups`, `-oidc-viewer-groups` (`PKI_DASH_OIDC_*_GROUPS`) | Grupos, separados por vírgula, de cada papel. |
| `-oidc-default-role` (`PKI_DASH_OIDC_DEFAULT_ROLE`) | `viewer` ou `operator` para quem não está em nenhum desses grupos. Vazio (o padrão) significa que não conseguem entrar. `admin` é recusado. |
| `-oidc-groups-claim` (`PKI_DASH_OIDC_GROUPS_CLAIM`) | A claim do ID token que lista os grupos. Padrão `groups`. Um caminho com pontos alcança o interior de objetos, por exemplo `realm_access.roles`. |
| `-oidc-username-claim` (`PKI_DASH_OIDC_USERNAME_CLAIM`) | A claim usada como nome da conta. Padrão `preferred_username`. |
| `-oidc-ca-file` (`PKI_DASH_OIDC_CA_FILE`) | Arquivo PEM com a CA que assinou o certificado do Keycloak, quando for uma CA privada. Use com a Root e a intermediária que você fez aqui. |

O emissor e a URL externa precisam ser `https`, exceto `localhost` enquanto você experimenta. O pki-dash se recusa a iniciar se o SSO estiver pela metade (por exemplo um client ID sem emissor, ou nenhum mapeamento de grupos), em vez de rodar sem o login que você acha que tem.

## Como os papéis são decididos

- O papel **mais alto** entre os grupos da pessoa vence: admin sobre operador sobre visualizador.
- Os grupos são comparados por inteiro, sem diferenciar maiúsculas e ignorando um `/` inicial: `pki-admins` não casa com `pki-admins-old`.
- O papel é recalculado a **cada login**. Se mudou, as outras sessões da pessoa terminam. Se ela não está mais em nenhum grupo mapeado, o próximo login é recusado.
- O papel de um usuário SSO não pode ser editado em **Usuários** (seria sobrescrito no próximo login), e ele não tem senha para redefinir. Um administrador ainda pode **desativá-lo** ali.
- Uma conta é amarrada ao id estável do usuário no provedor (`sub`) e ao emissor, nunca ao nome ou ao e-mail. Quem tem no Keycloak um nome igual ao de uma conta existente recebe um nome diferente (um sufixo curto é acrescentado) e não consegue tomar aquela conta.
- Se o último administrador ativo for um usuário SSO e o provedor o rebaixaria, o login é recusado em vez de deixar ninguém no comando.

## O que vale saber

- **Sair** encerra apenas a sessão do pki-dash, não a do Keycloak.
- Uma sessão do pki-dash dura no máximo 12 horas (30 minutos sem uso), independentemente do Keycloak. Se você remover alguém no Keycloak, a pessoa sai no próximo login ou quando a sessão acabar, **não instantaneamente**. Para cortar na hora, **desative-a** também em *Usuários*.
- O servidor busca a configuração do Keycloak no primeiro login de alguém, e de novo após uma falha, então o pki-dash sobe mesmo com o Keycloak fora do ar. O SSO fica indisponível até ele voltar; as contas locais continuam funcionando.
- O acesso ao pki-dash não é mais forte que o seu Keycloak: use o MFA e as políticas de senha dele.

## Quando não funciona

A tela de login mostra uma mensagem curta; o log do servidor tem o detalhe (`oidc: login refused`), e o log de auditoria registra os logins que falharam com o motivo.

| Mensagem | Causa usual |
|---|---|
| *Sua conta não tem permissão para usar esta aplicação* | A pessoa não está em nenhum grupo mapeado, ou os grupos não estão no **ID token**. Confira o mapper do passo 5 (Add to ID token) e os nomes que você informou. |
| *Essa autenticação expirou ou não foi iniciada aqui* | O login levou mais de 10 minutos, foi aberto em outro navegador, ou o navegador bloqueou o cookie. Garanta que `-external-url` é exatamente o endereço da barra do navegador, host incluso. |
| *A resposta do provedor de identidade não pôde ser verificada* | Segredo do cliente errado; a URI de retorno difere da cadastrada no Keycloak; o emissor nos tokens difere de `-oidc-issuer` (o Keycloak o monta a partir do endereço usado para acessá-lo); ou os relógios dos dois servidores estão muito diferentes. |
| *Não foi possível falar com o provedor de identidade agora* | O pki-dash não alcança a URL do emissor de onde está rodando (dentro de um container `localhost` é o próprio container), ou não confia no certificado do Keycloak: passe `-oidc-ca-file`. |
| O Keycloak mostra *Invalid parameter: redirect_uri* | A URI de retorno cadastrada no cliente não é exatamente `URL-EXTERNA/api/v1/auth/oidc/callback`. |

## O que fica registrado

`user.login` (detalhe `oidc`), `user.create` e `user.role_change` (ator `oidc`), e `user.login_failed` com `oidc:` e o motivo. O log de auditoria e sua cadeia de hashes funcionam como para as contas locais.
