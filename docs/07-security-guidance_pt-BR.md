# Protegendo a sua PKI

> Traduções: [en](07-security-guidance.md)

O pki-dash é para homelabs e redes internas, e uma CA privada é um alvo menor que uma pública. Mas a CA é o único componente cuja falha deixa alguém se passar por todos os hosts em que você confia, então os hábitos das PKIs maiores valem os poucos minutos que custam. Esta página diz quais importam e o que fazer quando algo dá errado.

**Tudo aqui é orientação, não garantia.** O pki-dash não tem garantia alguma, e todo o risco do uso é seu (veja o [README](../README_pt-BR.md)).

## O que um incidente real ensina

Em outubro de 2026 uma autoridade certificadora pública teve as chaves privadas de várias CAs intermediárias divulgadas como **recuperáveis a partir dos próprios certificados**: as chaves tinham sido geradas de forma incorreta. Quem tivesse uma dessas chaves poderia emitir certificados para qualquer nome de host, e todo cliente que confiasse na cadeia os aceitaria. Os navegadores bloquearam as intermediárias em poucos dias, mas muito software que não é navegador nunca confere a revogação e só se recupera quando a sua lista de autoridades confiáveis é atualizada (veja [a análise da Endor Labs](https://www.endorlabs.com/learn/emudhra-intermediate-ca-compromise-the-trust-stores-you-patched-and-the-ones-you-didnt-know-you-had), de onde vêm esses fatos).

A sua CA não é aquela, mas as mesmas três coisas decidem o tamanho do estrago de uma intermediária que vaze:

1. **O que ela podia emitir.** Sem limite, ela pode se passar por qualquer coisa. Limitada aos seus domínios, só por eles.
2. **Por quanto tempo a chave continua útil.** Uma vida mais curta encerra a exposição antes, mesmo para clientes que nunca conferem a revogação.
3. **Onde a sua Root é confiável.** Você não consegue limpar o que não sabia que tinha instalado.

## 1. Sempre limite para quais nomes uma intermediária pode emitir

Dê a toda intermediária uma **restrição de nomes**: uma extensão crítica que faz os clientes rejeitarem qualquer certificado que ela emita para um nome fora dos domínios que você listar. Se a chave vazar, o dano fica limitado a esses domínios.

- Nas instruções de assinatura do [fluxo da Root offline](03-offline-root_pt-BR.md#sempre-limite-para-quais-nomes-uma-intermediária-pode-emitir), liste os domínios (`lab`, `home.arpa`, o seu domínio) e use a receita do **openssl**. A tela avisa quando a lista está vazia.
- **A linha de comando do cfssl não consegue incluir a extensão**, então uma intermediária com restrição precisa ser assinada com o openssl.
- **Uma intermediária criada dentro do pki-dash, sob uma Root que o serviço guarda, não pode ter restrição.** Se você quer o limite, mantenha a Root offline e assine com o openssl. É mais um motivo para isso.
- O que ela limita: **nomes DNS**. A receita não restringe endereços IP, e-mails nem outros tipos de nome, então uma chave vazada ainda poderia emitir um certificado para um IP. A maior parte do que você protege com ela é alcançada por nome, mas conheça esse limite.
- Os clientes precisam aplicá-la. OpenSSL, Go, Java, os principais navegadores e a maioria das bibliotecas TLS aplicam; alguns softwares antigos ou embarcados não. Teste o seu: rode `openssl verify` num certificado de um nome fora da lista e veja falhar.
- O próprio pki-dash se recusa a emitir para nomes fora das restrições de uma intermediária, em vez de produzir um certificado que nenhum cliente aceitaria.

## 2. Mantenha as validades curtas

- **Intermediárias: dois anos por padrão** (você pode mudar, nunca além do fim da própria Root). Uma intermediária que vaze continua confiável, para os clientes que não conferem revogação, até expirar.
- **Certificados de serviço: o mais curtos que você conseguir renovar.** No máximo um ano; menos, se você automatizar a renovação.
- A Root pode ser longa (dez anos por padrão), porque é a única coisa que você mantém offline.

## 3. Saiba onde a Root é confiável

A confiança não fica num lugar só. O sistema operacional, cada navegador, cada runtime de linguagem e cada imagem de container podem ter a **sua própria** lista de autoridades, e instalar a Root em uma não a instala nas outras. No painel, **Instalar nos hosts** cobre as principais:

| Onde | Por que é separado |
|---|---|
| Debian, Ubuntu, RHEL, Fedora, Alpine, macOS, Windows | a lista do sistema |
| Firefox | mantém a própria lista |
| Java | cada JDK ou JRE tem o seu `cacerts`, e atualizações podem substituí-lo |
| Node.js | traz a própria lista e, por padrão, ignora a do sistema |
| Python (`requests`) | usa o pacote `certifi` que vem com ele |
| Containers | não herdam a confiança do host; a imagem precisa da sua |

Mantenha uma lista curta de **onde você instalou a sua Root**: hosts, imagens, runners de CI, dispositivos. No dia em que precisar removê-la ou trocá-la, essa lista é a diferença entre uma tarde e um mistério.

## 4. A revogação é uma defesa parcial

Os navegadores, em geral, não buscam CRLs de CAs privadas, e muito outro software também não. A revogação compensa onde algo que *você controla* a confere (veja [Revogação](04-revocation_pt-BR.md#quem-de-fato-consulta-uma-crl)). Para o resto, os controles são os acima: nomes limitados, vidas curtas e substituir o que foi comprometido.

## 5. Limite quem alcança a Root offline e registre cada assinatura

A Root é o segredo mais valioso de toda a PKI, e o único que o pki-dash não consegue proteger por você, porque ela **não está aqui**: vive numa máquina ou num meio que você mantém offline. O que segue é boa prática geral que você mesmo executa; o pki-dash não impõe nada disso.

- **Mantenha o círculo pequeno.** Todo mundo que alcança a chave da Root *ou* a senha dela é mais um caminho para o vazamento. Num homelab pode ser só você. Numa equipe, nomeie as poucas pessoas, anote os nomes e retire o acesso no dia em que alguém sair.
- **Não guarde a chave e a senha juntas.** A chave fica em mídia offline cifrada; a senha fica em outro lugar, e um backup da chave nunca fica ao lado dela.
- **Onde há mais de uma pessoa, use dois passos.** Uma pede a assinatura e outra a executa, ou ao menos espere um dia antes de assinar qualquer coisa inesperada.
- **Mantenha offline de verdade.** Uma máquina ou um meio de boot sem rede, usado para isso e nada mais, guardado trancado. Não assine "só desta vez" no seu notebook do dia a dia.
- **Registre cada assinatura.** O log de auditoria do painel registra o que acontece *no painel* (importar uma intermediária assinada, revogar, publicar uma CRL). A assinatura em si acontece na máquina offline e não deixa rastro ali, então mantenha um registro curto seu, num caderno ou num arquivo de texto guardado com a Root:

```
data        : 2026-10-22
quem        : quem assinou / quem pediu
por quê     : nova intermediária do laboratório (substitui "Home Services 2024")
o que       : CN=Home Services 2026, serial, 2 anos, path length 0,
              restrição de nomes: lab, home.arpa
conferido   : certificado relido com o openssl antes de sair da máquina
```

- **Leia o que você assinou antes de sair da máquina da Root.** Mostre com `openssl x509 -in inter.crt -noout -text` e confirme o assunto esperado, o path length 0, as restrições de nomes que você pretendia e uma validade que termina antes da Root. Ao importar, o painel confere o path length, o uso da chave, a validade e que ele corresponde à requisição, mas **não** exige restrição de nomes: essa parte é sua para olhar.
- **Teste o caminho de volta.** Uma vez, restaure a Root a partir do backup numa máquina offline, assine um certificado descartável e apague-o, para saber que o backup e a senha realmente funcionam. Mantenha ao menos duas cópias cifradas em lugares diferentes. Uma Root que você não consegue restaurar não tem backup.

## Se a chave de uma intermediária vazar

Aja nesta ordem. A rapidez importa mais que a perfeição.

1. **Pare de confiar nela a partir de agora.** No pki-dash, revogue-a (motivo *comprometimento da CA*) e publique a CRL da Root (veja [Revogando uma CA intermediária](04-revocation_pt-BR.md#revogando-uma-ca-intermediária)). Os clientes que conferem CRL vão recusá-la.
2. **Destrua a chave dela no pki-dash,** depois que a revogação estiver publicada (**Destruir chave**), para que uma cópia não saia dali.
3. **Crie uma nova intermediária,** agora com restrição de nomes e vida curta, assinada pela sua Root.
4. **Emita de novo os certificados de serviço a partir da nova intermediária e implante-os.** Os antigos continuam validando contra a intermediária antiga até ela expirar.
5. **Retire a confiança na intermediária antiga onde os clientes não conferem CRL.** Não há um jeito único: no Windows, `certutil -addstore Disallowed intermediaria-antiga.crt` como administrador; no macOS, marque o certificado como *Never Trust* no Acesso às Chaves; no Linux não há um modo limpo, para todo o sistema, de desconfiar de uma intermediária confiando na Root dela. Se você não consegue cobrir todos os clientes e a exposição importa, a resposta honesta é **trocar a Root** e reinstalar a confiança em todo lugar.
6. **Não presuma que você consegue ver o que foi emitido.** O log de auditoria lista o que o pki-dash emitiu, não o que alguém com a chave roubada emitiu em outro lugar. CAs privadas não têm um log público. Por isso limitar nomes e validades de antemão importa.

Se a chave da **Root** vazar, nada além de trocar a Root e reinstalar a confiança em todo lugar basta. Mantenha-a offline, cifrada e com backup longe da senha dela, como na [seção 5](#5-limite-quem-alcança-a-root-offline-e-registre-cada-assinatura).

## Chaves que vêm de fora

O pki-dash gera as próprias chaves com o gerador aleatório seguro do sistema operacional. Uma requisição assinada em outro lugar (o caminho por CSR) mantém a chave da intermediária dentro do pki-dash desde o começo. Para chaves públicas que **chegam de fora** (requisições de certificado, certificados importados), o pki-dash confere apenas que são grandes o bastante. Ele não distingue uma chave feita por um gerador defeituoso. Faça chaves com ferramentas confiáveis e desconfie de dispositivos com aleatoriedade pobre.

## Operando o serviço

- **Confira o que você baixa** (veja [Instalação](06-installation_pt-BR.md#confira-o-que-você-baixou)) e leia as notas de release antes de atualizar. Faça backup antes.
- Associe o listener a uma interface confiável; atrás de um proxy, liste **somente o proxy** como confiável (veja [Implantação](02-deployment_pt-BR.md#atrás-de-um-proxy-reverso)).
- Escolha **exatamente uma** forma de expor o serviço nas configurações. Duas ao mesmo tempo é tão errado quanto nenhuma, e depois de corrigir as configurações rode `systemctl reset-failed pki-dash` antes de reiniciar (veja [Instalação](06-installation_pt-BR.md#primeira-inicialização)).
- Guarde a senha mestra e os backups em lugares diferentes.
