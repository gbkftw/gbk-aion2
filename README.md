# gbk (app desktop)

Esqueleto em Tauri v2. Inclui: interface, detecção do processo do jogo, gravador de captura (.pcap) e janelas de overlay.
Ainda NÃO inclui o decodificador de pacotes: DPS, personagem e mascotes continuam simulados.

## Caminho mais fácil: instalador pronto pelo GitHub (sem instalar Rust nem Node)
1. Crie um repositório privado no GitHub e envie TODO o conteúdo desta pasta (inclusive a pasta oculta `.github`).
2. No repositório, abra Actions, escolha "Instalador do gbk" e clique em Run workflow.
3. Quando terminar (uns 10 a 15 minutos), abra a execução e baixe o artefato "gbk-instalador". Dentro vem o `.exe`.
4. Instale. O app pede administrador ao abrir (necessário para capturar pacotes).

## Compilar no seu computador
Requisitos: Node.js LTS, Rust (rustup.rs, com Build Tools do Visual Studio e "Desenvolvimento para desktop com C++") e o Npcap instalado.
O SDK do Npcap não é necessário: a biblioteca `pcap` 2.x carrega o Npcap em tempo de execução.
```
npm install
npm run build    (instalador em src-tauri\target\release\bundle\nsis)
npm run dev      (modo de desenvolvimento; abra o terminal como administrador)
```

## Observações
- Não foi possível compilar nem testar o Rust aqui. Se der erro de compilação, envie o texto do erro.
- Se o jogo usar UDP ou um relay local (VPN, redutor de ping), a detecção por TCP não basta. Ver docs/NOTAS.md.
