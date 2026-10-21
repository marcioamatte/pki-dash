# Contribuindo com o pki-dash

> Idioma principal: [English](CONTRIBUTING.md)

Obrigado por dedicar seu tempo. O pki-dash é um projeto pequeno, mantido por voluntários, e relatos de bugs, ideias, correções de documentação, traduções e código são todos bem-vindos.

Ao participar você concorda em seguir o [Código de Conduta](CODE_OF_CONDUCT_pt-BR.md).

O pki-dash gerencia autoridades certificadoras e chaves privadas, então leia primeiro o aviso do [README](README_pt-BR.md): ele é destinado a homelabs e ambientes internos e é fornecido **sem garantia**.

## Relatar um problema de segurança

**Não abra uma issue pública.** Use o [relato privado de vulnerabilidades](https://github.com/marcioamatte/pki-dash/security/advisories/new). Os detalhes estão em [SECURITY.md](SECURITY.md).

## Relatar um bug

[Abra uma issue](https://github.com/marcioamatte/pki-dash/issues/new) e inclua:

- a versão (`pki-dash --version`) e como você instalou (pacote, container, binário);
- o que você fez, o que esperava e o que aconteceu;
- as linhas de log relevantes (`journalctl -u pki-dash`, ou os logs do container). **Remova antes qualquer segredo**: tokens, senhas e chaves privadas nunca devem ir para uma issue.

## Sugerir uma mudança

Abra uma issue e descreva o problema que você quer resolver antes de escrever muito código. Uma conversa curta poupa tempo de todos, e algumas ideias não cabem no projeto. Estes itens estão **fora do escopo por enquanto**, então converse numa issue antes:

- OCSP (o projeto publica apenas CRLs);
- automação para o cert-manager do Kubernetes, ACME ou tokens de serviço (os certificados são baixados e instalados manualmente);
- importar uma CA intermediária junto com a chave privada (o caminho por CSR evita, de propósito, que chaves trafeguem);
- qualquer coisa voltada a PKI pública ou a cenários em que o comprometimento da CA seria crítico.

## Preparar o ambiente

Você precisa do Go (a versão do [go.mod](go.mod)), do Node.js (20.19+ ou 22.12+; o CI usa 24) e, para as verificações do container e da release, do Docker.

```bash
git clone git@github.com:marcioamatte/pki-dash.git && cd pki-dash
make build                         # compila a interface web e depois o binário Go em bin/
./bin/pki-dash -data-dir ./data -tls-self-signed
```

Abra <https://localhost:8443>. Na primeira execução o log mostra um token de setup de uso único. O binário embute o `web/dist`, então recompile a interface (`make ui`) depois de mudar o frontend. Para trabalhar rápido na interface, rode o servidor em modo HTTP puro e o servidor de desenvolvimento do Vite ao lado, que encaminha `/api` para a porta 8443:

```bash
./bin/pki-dash -data-dir ./data -insecure-http -listen 127.0.0.1:8443
cd web && npm run dev              # depois abra o endereço que ele mostrar
```

| Comando | O que faz |
|---|---|
| `make test` | Checagem de tipos e testes da interface, `go vet` e `go test -race` |
| `make check` | `make test`, mais a checagem dos avisos de terceiros, o `govulncheck` e o `npm audit` |
| `make docker` | Constrói a imagem e roda o teste de fumaça dela |
| `make snapshot` | Constrói uma release inteira (binários, pacotes, imagem) sem publicar; precisa do [GoReleaser](https://goreleaser.com/) |

## Fazer uma mudança

1. Faça um fork do repositório e crie uma branch a partir da `main`, com um nome que diga o que ela faz (`feat/...`, `fix/...`, `docs/...`).
2. Mantenha a mudança focada: uma ideia por pull request é mais fácil de revisar e de reverter.
3. Rode `make check` antes de enviar. O check `go` do CI precisa passar, e a `main` só muda por pull requests.
4. Abra um pull request e diga **o que** mudou, **por quê** e **como você verificou**. Cite a issue, se houver.
5. Um mantenedor revisa. A revisão é feita por voluntários e não tem prazo, então um lembrete depois de umas duas semanas é bem-vindo. O mantenedor faz o merge e publica as releases.

Escreva as mensagens de commit no imperativo ("Add X", "Fix Y") e use o corpo para explicar o *porquê* quando não for óbvio.

### O que procuramos

- **Testes que provem o comportamento.** Comportamento novo vem com testes, e o hábito do projeto é conferir o que importa também contra as ferramentas reais (openssl, cfssl, um Keycloak de verdade, um navegador de verdade), não só contra mocks. Diga no pull request o que você experimentou.
- **Código sensível à segurança é código cuidadoso.** Nunca registre segredos em log. Valide a entrada antes que ela chegue a uma linha de comando, a um nome de arquivo ou a uma receita que o usuário vai colar num shell. Mantenha o acesso novo à rede no mínimo e diga por que ele é necessário.
- **Dependência é uma decisão.** Módulos Go e pacotes npm ficam fixados em versões exatas, o npm roda com `ignore-scripts`, as GitHub Actions são fixadas pelo SHA do commit e as imagens base pelo digest. Uma dependência nova precisa de um motivo, e é preciso rodar de novo `./scripts/gen-notices.sh > THIRD_PARTY_NOTICES.md` para as licenças continuarem corretas. O Dependabot propõe atualizações do que já existe.
- **Go:** `gofmt`, `go vet` e os testes com `-race` sem avisos. Fora dos testes, a biblioteca do cfssl é usada somente dentro de `internal/ca`.
- **Interface web:** Svelte 5 (runes), TypeScript e Tailwind. A Content-Security-Policy proíbe scripts e estilos inline. Todo texto visível vai em **ambos** `web/src/lib/messages/en.ts` e `pt-BR.ts` (os tipos fazem uma chave faltando virar erro de compilação). Confira uma mudança de interface em larguras de celular e de desktop, no claro e no escuro.
- **Documentação:** inglês primeiro, com o gêmeo em português do Brasil (`*_pt-BR.md`) acompanhando. Se você não escreve português, diga isso no pull request e um mantenedor traduz.

### Usando ferramentas de IA

Este projeto foi construído em parceria com um assistente de IA, então não há regra contra isso. A regra é a mesma de qualquer código: **você é responsável pelo que envia.** Leia, entenda, rode e diga no pull request que uma ferramenta ajudou.

## Licença

O pki-dash está sob a [licença MIT](LICENSE). Ao contribuir você concorda que sua contribuição também é licenciada sob ela.
