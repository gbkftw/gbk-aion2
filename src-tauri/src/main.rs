#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use sysinfo::{ProcessesToUpdate, System};
use tauri::{Emitter, Manager, State};

#[derive(Default)]
struct Rec(Mutex<Option<Arc<AtomicBool>>>);

#[derive(Serialize)]
struct Dev {
    name: String,
    desc: String,
}
#[derive(Serialize)]
struct Server {
    ip: String,
    port: u16,
    pid: u32,
}
#[derive(Serialize)]
struct Conn {
    name: String,
    pid: u32,
    ip: String,
    port: u16,
}
#[derive(Serialize, Clone)]
struct Stats {
    packets: u64,
    bytes: u64,
}

struct Link {
    name: String,
    pid: u32,
    local: String,
    ip: String,
    port: u16,
}

/// Todas as conexões TCP estabelecidas (fora de loopback) com o nome do processo dono.
fn all_links() -> Result<Vec<Link>, String> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let socks = get_sockets_info(AddressFamilyFlags::IPV4, ProtocolFlags::TCP).map_err(|e| e.to_string())?;
    let mut out = vec![];
    for s in socks {
        if let ProtocolSocketInfo::Tcp(t) = s.protocol_socket_info {
            if t.state != TcpState::Established || t.remote_addr.is_loopback() {
                continue;
            }
            let Some(pid) = s.associated_pids.first().copied() else { continue };
            let name = sys
                .process(sysinfo::Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_else(|| "?".into());
            out.push(Link { name, pid, local: t.local_addr.to_string(), ip: t.remote_addr.to_string(), port: t.remote_port });
        }
    }
    Ok(out)
}

fn of_process(process: &str) -> Result<Vec<Link>, String> {
    Ok(all_links()?.into_iter().filter(|l| l.name.eq_ignore_ascii_case(process)).collect())
}

fn bpf(links: &[Link]) -> String {
    if links.is_empty() {
        return "host 192.0.2.1".into();
    }
    let parts: Vec<String> = links.iter().map(|l| format!("(host {} and port {})", l.ip, l.port)).collect();
    format!("tcp and ({})", parts.join(" or "))
}

/// Placas de rede vistas pelo Npcap.
#[tauri::command]
fn list_devices() -> Result<Vec<Dev>, String> {
    pcap::Device::list()
        .map_err(|e| e.to_string())
        .map(|v| v.into_iter().map(|d| Dev { desc: d.desc.unwrap_or_default(), name: d.name }).collect())
}

/// Conexões abertas por todos os processos, com os que parecem ser do Aion primeiro.
#[tauri::command]
fn list_connections() -> Result<Vec<Conn>, String> {
    let mut v: Vec<Conn> = all_links()?
        .into_iter()
        .map(|l| Conn { name: l.name, pid: l.pid, ip: l.ip, port: l.port })
        .collect();
    v.sort_by_key(|c| (!c.name.to_lowercase().contains("aion"), c.name.clone()));
    Ok(v)
}

/// Conexões do processo do jogo (nome parcial, sem diferenciar maiúsculas).
#[tauri::command]
fn find_game_server(process: String) -> Result<Vec<Server>, String> {
    let want = process.to_lowercase();
    let out: Vec<Server> = all_links()?
        .into_iter()
        .filter(|l| l.name.to_lowercase().contains(&want))
        .map(|l| Server { ip: l.ip, port: l.port, pid: l.pid })
        .collect();
    if out.is_empty() {
        return Err(format!("Nenhuma conexão do processo '{process}'. Abra o jogo primeiro."));
    }
    Ok(out)
}

/// Grava o tráfego do processo do jogo em um .pcap (uso de desenvolvimento).
/// A placa de rede é escolhida pelo IP local da conexão, a menos que `device` seja informado.
/// O filtro é atualizado a cada 3 s, para acompanhar conexões novas do jogo.
#[tauri::command]
fn start_record(app: tauri::AppHandle, st: State<Rec>, process: String, device: Option<String>) -> Result<String, String> {
    let mut g = st.0.lock().unwrap();
    if g.is_some() {
        return Err("Já existe uma gravação em andamento.".into());
    }
    let links = of_process(&process)?;
    if links.is_empty() {
        return Err(format!("O processo '{process}' não tem conexões abertas. Abra o jogo primeiro."));
    }
    let dev = match device.filter(|d| !d.is_empty()) {
        Some(d) => d,
        None => pcap::Device::list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|d| d.addresses.iter().any(|a| a.addr.to_string() == links[0].local))
            .map(|d| d.name)
            .ok_or("Não achei a placa de rede desta conexão. Escolha a placa manualmente.")?,
    };
    let f0 = bpf(&links);
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let dir = std::env::var("USERPROFILE").map(|p| format!("{p}\\Documents")).unwrap_or_else(|_| ".".into());
    let path = format!("{dir}\\gbk-captura-{secs}.pcap");
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let (s2, p2, proc2, f2) = (stop.clone(), path.clone(), process.clone(), f0.clone());
    std::thread::spawn(move || {
        let open = || -> Result<_, String> {
            let mut cap = pcap::Capture::from_device(dev.as_str())
                .map_err(|e| e.to_string())?
                .promisc(false)
                .snaplen(65535)
                .immediate_mode(true)
                .timeout(200)
                .open()
                .map_err(|e| e.to_string())?;
            cap.filter(&f2, true).map_err(|e| e.to_string())?;
            let file = cap.savefile(&p2).map_err(|e| e.to_string())?;
            Ok((cap, file))
        };
        let (mut cap, mut file) = match open() {
            Ok(v) => {
                let _ = tx.send(Ok(()));
                v
            }
            Err(e) => {
                let _ = tx.send(Err(e));
                return;
            }
        };
        let mut cur = f0;
        let (mut n, mut b) = (0u64, 0u64);
        let (mut last, mut last_f) = (std::time::Instant::now(), std::time::Instant::now());
        while !s2.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(p) => {
                    file.write(&p);
                    n += 1;
                    b += p.header.len as u64;
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(_) => break,
            }
            if last_f.elapsed().as_secs() >= 3 {
                if let Ok(l) = of_process(&proc2) {
                    let f = bpf(&l);
                    if f != cur && cap.filter(&f, true).is_ok() {
                        cur = f;
                    }
                }
                last_f = std::time::Instant::now();
            }
            if last.elapsed().as_millis() > 500 {
                let _ = app.emit("capture-stats", Stats { packets: n, bytes: b });
                last = std::time::Instant::now();
            }
        }
        let _ = file.flush();
        let _ = app.emit("capture-stats", Stats { packets: n, bytes: b });
    });
    rx.recv().map_err(|e| e.to_string())??;
    *g = Some(stop);
    Ok(path)
}

#[tauri::command]
fn stop_record(st: State<Rec>) {
    if let Some(s) = st.0.lock().unwrap().take() {
        s.store(true, Ordering::Relaxed);
    }
}

#[tauri::command]
fn toggle_overlay(app: tauri::AppHandle, label: String) {
    if let Some(w) = app.get_webview_window(&label) {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
        } else {
            let _ = w.show();
            let _ = w.set_always_on_top(true);
        }
    }
}

fn main() {
    tauri::Builder::default()
        .manage(Rec::default())
        .invoke_handler(tauri::generate_handler![
            list_devices,
            list_connections,
            find_game_server,
            start_record,
            stop_record,
            toggle_overlay
        ])
        .run(tauri::generate_context!())
        .expect("erro ao iniciar o gbk");
}
