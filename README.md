# OwnerLock — Paper 26.3

Plugin administrativo com autenticação do proprietário, comandos registrados pela API de lifecycle do Paper, auditoria e workflow de compilação no GitHub Actions.

> **Estado:** código-fonte pronto para revisão e compilação automática. A compilação precisa passar no GitHub Actions e ser testada num servidor Paper descartável antes de usar em produção.

## Requisitos

- Minecraft/Paper 26.3 compatível com a API usada no projeto
- JDK 25
- Gradle 9.1 ou superior (a workflow configura Gradle 9.1.0)
- Acesso de rede ao repositório Maven oficial do Paper

## Conteúdo do repositório

```text
OwnerLock/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE/
│   └── workflows/build.yml
├── src/main/java/br/com/nexodev/ownerlock/OwnerLockPlugin.java
├── src/main/resources/config.yml
├── src/main/resources/plugin.yml
├── .gitattributes
├── .gitignore
├── build.gradle
├── build.sh
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
└── settings.gradle
```

## Criar o repositório público

1. No GitHub, crie um repositório chamado **OwnerLock** com visibilidade **Public**.
2. Não selecione a opção para gerar README, `.gitignore` ou licença, pois esses arquivos já estão no pacote.
3. Extraia este ZIP.
4. Envie **o conteúdo de dentro** da pasta `OwnerLock-Paper-26.3-v2` para a raiz do repositório. A pasta `.github` deve ficar diretamente na raiz do repositório.
5. Faça commit na branch `main`.

## Compilação automática e download do JAR

A workflow `.github/workflows/build.yml` roda em `push`, `pull_request` e manualmente via `workflow_dispatch`.

1. Abra a aba **Actions** do repositório.
2. Se necessário, habilite GitHub Actions para o repositório.
3. Selecione **Build OwnerLock** e clique em **Run workflow**, ou faça um commit para `main`.
4. Aguarde a execução ficar verde.
5. Na página da execução, em **Artifacts**, baixe `OwnerLock-Paper-26.3`. O ZIP do artefato contém `OwnerLock-2.0.0-mc26.3.jar`.

Se a compilação falhar, abra os logs da etapa **Compile and package**; não use um JAR antigo ou renomeado como substituto.

## Compilar localmente

Com JDK 25 e Gradle instalado:

```sh
gradle --no-daemon clean build
```

Ou execute `./build.sh` em Linux/macOS. O arquivo gerado deve ser:

```text
build/libs/OwnerLock-2.0.0-mc26.3.jar
```

## Configuração inicial

1. Copie o JAR compilado para `plugins/` e inicie o servidor de teste.
2. Edite `plugins/OwnerLock/config.yml` com `owner-name` e o UUID oficial em `owner-uuid`.
3. Em modo online, mantenha `online-mode=true` em produção.
4. Em modo offline, defina `owner-secret` com uma senha exclusiva de pelo menos 16 caracteres antes da primeira inicialização. O plugin transforma o segredo em hash salgado em `auth.yml` e limpa o campo em texto puro de `config.yml`.
5. Teste login, logout, OP e comandos em um servidor descartável antes de usar em qualquer ambiente importante.

## Aviso de segurança

`online-mode=false` não autentica contas Minecraft. Nick e UUID offline não comprovam identidade; a senha protege apenas o acesso implementado pelo OwnerLock. Use modo offline somente em teste privado e não reutilize a senha da conta Minecraft. A execução como console é altamente privilegiada e deve permanecer restrita ao proprietário autenticado.

## Licença

MIT. Consulte `LICENSE`.
