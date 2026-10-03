# 🛡️ KeePass Web Vault

<p align="center">
  <strong>Um leitor e gerenciador web moderno, rápido e 100% offline para bancos de dados de senhas do KeePass (.kdbx).</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License MIT" />
  <img src="https://img.shields.io/badge/KDBX-v3%20%7C%20v4-emerald.svg" alt="KDBX 3 & 4" />
  <img src="https://img.shields.io/badge/KDF-Argon2id%20%7C%20Argon2d%20%7C%20AES-cyan.svg" alt="KDF Algorithms" />
  <img src="https://img.shields.io/badge/Security-100%25%20Client--Side-brightgreen.svg" alt="Client Side Security" />
  <img src="https://img.shields.io/badge/PRs-welcome-orange.svg" alt="PRs Welcome" />
</p>

---

## 🔒 Segurança e Privacidade em Primeiro Lugar

O **KeePass Web Vault** foi projetado com uma arquitetura estritamente **Zero-Knowledge / 100% Client-Side**:
- **Nenhum Dado Sai do Seu Dispositivo**: Toda a leitura, descriptografia e manipulação acontecem em memória dentro da sandbox do navegador.
- **WebCrypto API & WebAssembly**: As operações de criptografia utilizam a API nativa `window.crypto.subtle` e hashes Argon2 de alta performance compilados em WebAssembly (`hash-wasm`).
- **Sem Telemetria**: Sem analytics, sem rastreadores, sem dependências remotas que interceptem dados.
- **Limpeza de Memória no Bloqueio**: Ao bloquear o cofre ou após inatividade, todas as referências descriptografadas em memória são destruídas.

---

## ✨ Recursos

- 📂 **Suporte Completo ao KeePass**:
  - Compatível com bases do **KeePass 2.x** e **KeePassXC** (`.kdbx`).
  - Suporte aos algoritmos modernos de KDF: **Argon2id**, **Argon2d** e **AES-KDF**.
  - Autenticação por Senha Mestra e suporte opcional a Arquivo Chave (`.key`).
- 🎨 **Interface Moderna & Responsiva**:
  - Tema escuro *Glassmorphism* com paleta cuidadosamente selecionada (Slate, Cyan e Emerald).
  - Ícones vetorizados com [Lucide](https://lucide.dev/).
  - Árvore hierárquica de grupos/pastas e contador de entradas.
  - Sistema de **Favoritos** com estrela para acesso rápido.
- ⚡ **Busca Rápida & Atalhos**:
  - Pesquisa instantânea por título, login, URL, tags ou anotações (`Ctrl + K` ou `Ctrl + F`).
  - Ordenação por título (A-Z / Z-A), usuário ou data de modificação.
- 🔑 **Visualização e Cópia Seguras**:
  - Senhas mascaradas por padrão, com revelação controlada via ícone de olho.
  - Cópia para a área de transferência com 1 clique e notificação toast.
  - Medidor de força de senha em tempo real (entropia em bits, complexidade e comprimento).
- ⏱️ **Autenticador 2FA / TOTP Integrado**:
  - Gera códigos temporários de 6 dígitos em tempo real se a credencial contiver chave TOTP (padrão RFC 6238 ou formato KeePassXC).
  - Barra de progresso visual de 30 segundos sincronizada com o relógio.
- 🛠️ **Ferramentas Inclusas**:
  - **Gerador de Senhas Fortes**: ajuste de tamanho (8 a 64 caracteres), maiúsculas, minúsculas, números, caracteres especiais e opção de excluir caracteres ambíguos.
  - **Exportação de Dados**: download dos dados em formato **CSV** (compatível com Excel/Bitwarden) ou **JSON**.
  - **Bloqueio Automático por Inatividade**: cronômetro regressivo com bloqueio de segurança.
  - **Cofre de Exemplo**: botão *"Testar Exemplo"* para testar a aplicação com 1 clique sem precisar do seu próprio arquivo.

---

## 🚀 Como Executar Localmente

### Pré-requisitos
- [Node.js](https://nodejs.org/) versão 18 ou superior.

### Instalação

1. Clone o repositório:
```bash
git clone https://github.com/ohguinascimento/keepass-web-vault.git
cd keepass-web-vault
```

2. Instale as dependências:
```bash
npm install
```

3. Inicie o servidor de desenvolvimento:
```bash
npm run dev
```

4. Acesse no navegador:
```
http://localhost:5173
```

*(No Windows, você também pode simplesmente dar duplo clique no arquivo `iniciar.bat`)*

---

## 📦 Build para Produção

Para gerar o bundle estático otimizado:
```bash
npm run build
```
Os arquivos prontos para publicação estarão no diretório `dist/`. Como a aplicação é 100% estática, ela pode ser hospedada gratuitamente em qualquer provedor estático (GitHub Pages, Vercel, Cloudflare Pages, Netlify).

---

## 🛠️ Tecnologias Utilizadas

- **[Vite](https://vitejs.dev/)**: Ferramenta de build rápida e leve.
- **[kdbxweb](https://github.com/keeweb/kdbxweb)**: Parser e motor KDBX em JavaScript.
- **[hash-wasm](https://github.com/Daninet/hash-wasm)**: Implementação WebAssembly ultrarrápida de Argon2id e Argon2d.
- **[Lucide Icons](https://lucide.dev/)**: Ícones vetoriais modernos.
- **WebCrypto API**: Criptografia de nível militar diretamente na engine do browser.

---

## 🤝 Como Contribuir

Contribuições são muito bem-vindas! Sinta-se à vontade para:
1. Fazer um Fork do projeto.
2. Criar uma Branch com sua feature/correção (`git checkout -b feature/minha-feature`).
3. Fazer o Commit das suas alterações (`git commit -m 'Adiciona funcionalidade X'`).
4. Fazer o Push para a Branch (`git push origin feature/minha-feature`).
5. Abrir um Pull Request.

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](./LICENSE) para mais informações.
