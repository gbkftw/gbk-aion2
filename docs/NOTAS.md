# Notas sobre captura e protocolo

Fonte: leitura do código público do A2Tools (GPL-3.0, github.com/taengu/A2Tools-DPS-Meter) e das notas de versão de outros medidores.
São observações, não código copiado. Se o gbk reaproveitar código do A2Tools, o gbk precisa ser GPL-3.0.

## O que se sabe
- O A2Tools é um app Tauri (Rust) com captura passiva via Npcap. Exige administrador.
- A porta de combate é descoberta pelo conteúdo dos pacotes (assinatura de bytes), por placa de rede, e não só pelo processo.
  Há tratamento para relay local (VPN ou redutor de ping): o tráfego em loopback tem preferência após cerca de 2,5 s.
- Registro do próprio personagem (marcador `33 36`): nome, servidor, classe e nível. É enviado ao carregar zonas e a cada poucos minutos,
  às vezes dentro de pacotes agrupados e comprimidos (LZ4), então um medidor aberto no meio da sessão pode perder o nível por um tempo.
- Lista do grupo: poder de combate e nível de equipamento só aparecem para membros do grupo.
- Outros registros citados: atributos próprios (`4A 36`), dono de invocações (`04 8D`), lista de energia (`0B 61`).
- Chefes: códigos de spawn 0x3640 e 0x3641 (notas de versão do aion2t-dps-meter).
- Os códigos mudam com patches: manter o decodificador é trabalho contínuo.

## O que NÃO encontrei
- Decodificação de equipamentos completos, progresso de mascotes ou cubos misteriosos. No A2Tools, "pet" significa invocação em combate.
  Isso exige capturas e análise novas.

## Privacidade (modelo a seguir)
- Nada é enviado sem a pessoa aprovar. Envio automático desligado por padrão.
- Vínculo da conta: o app abre o navegador, a pessoa aprova, e o app guarda um token criptografado (DPAPI do Windows).
- Nunca enviar pacotes brutos, só dados já decodificados e que a pessoa escolheu compartilhar.
