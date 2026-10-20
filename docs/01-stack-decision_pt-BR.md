# pki-dash: Decisão de Stack (rascunho)

> Status: aprovado pelo mantenedor em 2026-10-20. Idioma principal: [English](01-stack-decision.md). Em caso de divergência, vale a versão em inglês.

## 1. Resultado das verificações

Antes de escolher, verificamos se o cfssl pode ser usado como **biblioteca Go** em vez de processo filho. Uma prova descartável (fora do repositório) clonou o cfssl e compilou um programa que:

- gerou a chave da Root CA **em memória** (`ecdsa.GenerateKey`) e criou o certificado raiz com `initca.NewFromSigner`;
- montou um `local.NewSigner(crypto.Signer, cert, ...)` com essa chave em memória;
- gerou um CSR e o assinou como **CA intermediária** (`signer.Sign`) com um perfil `CAConstraint` (path length 0).

Achados:

| Pergunta | Resultado |
|---|---|
| O cfssl assina sem arquivos de chave em disco? | **Sim.** `local.NewSigner` aceita qualquer `crypto.Signer`. As chaves podem ser decifradas só em memória e só quando necessárias, e isso deixa o caminho aberto para PKCS#11/HSM no futuro. |
| Compila sem CGO? | **Sim.** A prova compilou com `CGO_ENABLED=0` (binário de ~19 MB). Os drivers SQLite/MySQL/Postgres *não* entram, a menos que o `certdb` seja importado. Isso permite binário estático e imagem mínima. |
| Licenças das dependências | As dependências transitivas do caminho de assinatura (`x/crypto`, `x/net`, `x/text`, `protobuf`, `zcrypto`, `zlint`, `certificate-transparency-go`, `publicsuffix-go`, `go-toml`, `klog`, `logr`, `sqlx`) são todas MIT, BSD ou Apache-2.0. Nenhuma conflita com distribuição MIT. Falta uma checagem formal no CI. |
| Saúde do projeto | Ativo: último commit em 2026-10-06 (ex.: suporte a chaves pós-quânticas ML-DSA, novos alvos de release). Exige uma toolchain Go muito recente (`go 1.27` no `go.mod`), então acompanharemos o Go de perto. |

Ressalvas:

- A API de biblioteca do cfssl **não** é uma API pública estável. Vamos isolá-la atrás de uma interface própria (`internal/ca`) e fixar uma versão exata do cfssl.
- O cfssl registra logs pelo logger próprio (`[INFO] signed certificate with serial...`). Precisamos redirecionar/filtrar para nada sensível vazar para os logs, e usar nosso log de auditoria como fonte da verdade.
- Precisamos verificar com testes próprios que os certificados emitidos são o esperado (extensões, path length, key usages), sem confiar em padrões.

## 2. Decisão

| Camada | Escolha | Por quê |
|---|---|---|
| Backend | **Go**, cfssl como **biblioteca embutida** | Binário estático único; sem processo filho; sem API HTTP do cfssl escutando, nem em loopback; menor superfície de ataque. |
| Container | `distroless/static` (ou `scratch`), não-root, filesystem raiz somente leitura, um volume de dados | Imagem mínima, sem shell, sem gerenciador de pacotes. |
| Frontend | **Svelte + TypeScript + Tailwind**, compilado para assets estáticos e embutido no binário Go (`go:embed`) | Bundle pequeno, rápido, visual moderno; bem menos dependências em runtime que uma árvore React típica, o que importa para a exposição a supply chain do npm. Sem Node em produção. |
| Armazenamento | **SQLite**, driver Go puro (`modernc.org/sqlite`) | Um arquivo no volume, transacional, sem CGO. |
| Segredos em repouso | Chaves das CAs criptografadas na aplicação: senha mestra → Argon2id → AES-256-GCM (envelope encryption: uma chave de dados por chave de CA, protegida por uma chave derivada da senha) | Não depende de criptografia no nível do banco. Permite trocar a senha sem recriptografar todas as chaves. |
| Autenticação | Usuários locais com hash Argon2id; sessões no servidor em cookies (`HttpOnly`, `Secure`, `SameSite=Strict`); proteção CSRF; controle por papéis. OIDC (Keycloak primeiro) via `coreos/go-oidc` depois. | Sessões no servidor são revogáveis, ao contrário de JWTs de longa duração. |
| Transporte | Somente HTTPS. O painel serve o próprio TLS e pode emitir seu certificado a partir da própria CA na primeira execução. | Dogfooding, e nenhum download de chave em texto claro. |
| Hardening HTTP | CSP estrita (sem scripts inline), HSTS, `X-Content-Type-Options`, `Referrer-Policy`, rate limit e bloqueio no login, limite de tamanho de requisição | Base padrão para uma UI administrativa. |

## 3. Frontend: por que Svelte e não React

Ambos funcionariam. Os fatores decisivos para este projeto:

- **Supply chain.** Menos dependências, e menores, significam menor superfície de auditoria para uma ferramenta sensível. O Svelte elimina o runtime na compilação; um app React típico traz um ecossistema maior de pacotes transitivos.
- **Desempenho e tamanho.** Bundles menores e sem custo de virtual DOM, bom para algo embutido em um binário.
- **Simplicidade.** Menos boilerplate para telas cheias de formulários, que é a maior parte desta UI.
- **Trade-off reconhecido:** o React tem mais contribuidores e um ecossistema de componentes maior. Se o alcance de contribuidores passar a pesar mais, o desenho API-first (abaixo) permite trocar o frontend sem tocar no backend.

## 4. Esboço da arquitetura

```
Navegador ──HTTPS──▶ Binário Go
                       ├─ UI estática embutida (build Svelte)
                       ├─ API REST (JSON, versionada: /api/v1)
                       ├─ auth / sessões / RBAC / auditoria
                       ├─ internal/ca  (nossa interface)
                       │     └─ biblioteca cfssl (initca, csr, signer/local)
                       └─ SQLite (usuários, metadados de CAs, chaves cifradas, certificados emitidos, auditoria)
```

A API é o contrato. A UI é apenas um cliente dela, o que também abre espaço para CLI ou automação no futuro.

## 5. Base de supply chain e qualidade

- Dependências fixadas com lockfiles (`go.sum`, `package-lock.json`); somente `npm ci`; versão exata do cfssl.
- CI: `go vet`, testes com race detector, `govulncheck`, `staticcheck`/`golangci-lint`, `npm audit`, checagem de licenças, scan da imagem (ex.: Trivy), geração de SBOM.
- Builds reprodutíveis e artefatos de release assinados (ex.: cosign) antes do primeiro release público.
- Testes que fazem o parse dos certificados emitidos e verificam restrições (flag de CA, path length, key usage, SANs, validade), e não só que a assinatura "funcionou".
- Política de segurança (`SECURITY.md`) com canal privado de reporte antes de publicar no GitHub.

## 6. Decisões confirmadas

1. Frontend: Svelte.
2. Algoritmos de chave: ECDSA P-384 (Root), P-256 (intermediárias e folhas), RSA 3072/4096 opcional, Ed25519 desligado por padrão.
3. Validades padrão: Root 10 anos, intermediárias 3–5 anos, folhas ≤ 1 ano, com aviso na UI acima de 398 dias.
4. Repositório: `git@github.com:marcioamatte/pki-dash.git`; module path Go `github.com/marcioamatte/pki-dash`.
