use std::{
    collections::HashSet,
    fs,
    path::Path,
    sync::Arc,
    time::Duration,
};
use clap::Parser;
use rusqlite::{params, Connection};
use tokio::{
    process::Command,
    sync::{Mutex, Semaphore},
    time::{interval, sleep},
    fs::OpenOptions,
    io::AsyncWriteExt,
};
use chrono::Local;
use futures::stream::{FuturesUnordered, StreamExt};
use anyhow::{anyhow, Context};
use regex::Regex;

#[derive(Parser)]
#[command(about = "Ferramenta Avançada de Monitoramento para Bug Bounty")]
struct Args {
    #[arg(short, long, help = "Ativa modo verboso")]
    verbose: bool,

    #[arg(short, long, help = "Domínio para monitorar", conflicts_with_all = &["import_list", "list_contains", "count", "mass_scan", "remove"])]
    domain: Option<String>,

    #[arg(
        long = "import-list",
        alias = "import_list",
        value_name = "FILE",
        help = "Importa subdomínios de um arquivo",
        conflicts_with_all = &["domain", "list_contains", "count", "mass_scan", "remove"]
    )]
    import_list: Option<String>,

    #[arg(
        long,
        value_name = "PATTERN",
        help = "Lista subdomínios que contenham o padrão",
        conflicts_with_all = &["domain", "import_list", "count", "mass_scan", "remove"]
    )]
    list_contains: Option<String>,

    #[arg(long, help = "Exibe quantidade total de subdomínios", conflicts_with_all = &["domain", "import_list", "list_contains", "mass_scan", "remove"])]
    count: bool,

    #[arg(
        long = "mass-scan",
        value_name = "FILE",
        help = "Escaneia múltiplos domínios de um arquivo",
        conflicts_with_all = &["domain", "import_list", "list_contains", "count", "remove"]
    )]
    mass_scan: Option<String>,

    #[arg(
        long = "remove",
        value_name = "PATTERN",
        help = "Remove subdomínios que contenham o padrão",
        conflicts_with_all = &["domain", "import_list", "list_contains", "count", "mass_scan"]
    )]
    remove: Option<String>,

    #[arg(
        long = "output-dir",
        value_name = "DIRECTORY",
        help = "Diretório para salvar todos os resultados"
    )]
    output_dir: Option<String>,
}

const DB_FILE: &str = "monrust.db";
const SCAN_RESULTS_DIR: &str = "scan_results";
const DEFAULT_SCAN_INTERVAL: u64 = 10;
const API_WORDLIST_URL: &str = "https://gist.githubusercontent.com/helcaraxeals/7c45201b1c957ecea82ef7800da4bfa4/raw/b84a7364f33f2eb14aad68149302077649d70acc/api_wordlist.txt";
const GENERAL_WORDLIST_URL: &str = "https://raw.githubusercontent.com/onvio/wordlists/master/words_and_files_top5000.txt";
const DEFAULT_THREADS: usize = 50;
const DEFAULT_SEVERITY: &str = "medium,high,critical";
const TOP_1000_PORTS: &str = "80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Aumentar limite de arquivos abertos
    tokio::task::spawn_blocking(|| {
        let _ = rlimit::increase_nofile_limit(100_000).unwrap();
    }).await?;

    let args = Args::parse();
    
    // Determinar diretório de saída
    let output_dir = args.output_dir.as_deref().unwrap_or(SCAN_RESULTS_DIR);
    
    // Criar diretório para resultados
    fs::create_dir_all(output_dir).context("Falha ao criar diretório de resultados")?;
    
    let scan_interval = if args.mass_scan.is_some() {
        0
    } else {
        DEFAULT_SCAN_INTERVAL
    };

    if args.verbose {
        println!("[⚙️ CONFIG] Severidade: {}", DEFAULT_SEVERITY);
        println!("[⚙️ CONFIG] Threads: {}", DEFAULT_THREADS);
        println!("[⚙️ CONFIG] Intervalo de scan: {} minutos", scan_interval);
        println!("[⚙️ CONFIG] Diretório de resultados: {}", output_dir);
    }

    let conn = Arc::new(Mutex::new(init_db()?));

    if let Err(e) = download_wordlist("api_wordlist.txt", API_WORDLIST_URL).await {
        eprintln!("❌ Falha ao baixar API wordlist: {}", e);
    }
    if let Err(e) = download_wordlist("general_wordlist.txt", GENERAL_WORDLIST_URL).await {
        eprintln!("❌ Falha ao baixar wordlist geral: {}", e);
    }

    if args.domain.is_none()
        && args.import_list.is_none()
        && args.list_contains.is_none()
        && !args.count
        && args.mass_scan.is_none()
        && args.remove.is_none()
    {
        println!(
            r#"
🛠️ MonRust - Monitoramento de Subdomínios (Bug Bounty Edition)

OPÇÕES:
  -d, --domain <DOMÍNIO>         Monitora um domínio recursivamente
  --import-list <ARQUIVO>        Importa subdomínios de um arquivo
  --list_contains <PADRÃO>       Lista subdomínios que contenham o padrão
  --count                        Exibe quantidade total de subdomínios
  --mass-scan <ARQUIVO>          Escaneia múltiplos domínios de um arquivo
  --remove <PADRÃO>              Remove subdomínios que contenham o padrão
  --output-dir <DIRETÓRIO>       Diretório para salvar todos os resultados

EXEMPLOS:
  monRust -d example.com             # Monitora um único domínio
  monRust --mass-scan dominios.txt   # Escaneia em massa
  monRust --remove teste             # Remove subdomínios com 'teste'
"#
        );
        return Ok(());
    }

    if let Some(pattern) = args.remove {
        println!("🗑️ Removendo subdomínios que contêm: {}", pattern);
        let conn = conn.lock().await;
        let mut stmt = conn.prepare("DELETE FROM domains WHERE name LIKE '%' || ?1 || '%'")?;
        let count = stmt.execute(params![pattern])?;
        println!("✅ {} subdomínios removidos", count);
        return Ok(());
    }

    if let Some(file) = args.import_list.clone() {
        println!("📥 Importando subdomínios do arquivo: {}", file);
        let contents = fs::read_to_string(&file)?;
        let mut new_subs = HashSet::new();
        let conn = conn.lock().await;
        for line in contents.lines() {
            let sub = line.trim();
            if !sub.is_empty() {
                match conn.execute(
                    "INSERT OR IGNORE INTO domains (name, seen_at, processed) VALUES (?1, ?2, 0)",
                    params![sub, Local::now().to_rfc3339()],
                ) {
                    Ok(1) => println!("✅ Subdomínio adicionado ao banco: {}", sub),
                    Ok(0) => println!("ℹ️ Subdomínio já existente: {}", sub),
                    Ok(_) => (),
                    Err(e) => eprintln!("❌ Erro ao inserir subdomínio '{}': {}", sub, e),
                }
                new_subs.insert(sub.to_string());
            }
        }
        println!("✅ {} subdomínios importados com sucesso!", new_subs.len());
        return Ok(());
    }

    if let Some(pat) = args.list_contains {
        println!("🔎 Buscando subdomínios com padrão: {}", pat);
        let conn = conn.lock().await;
        let mut stmt = conn.prepare("SELECT name FROM domains WHERE name LIKE '%' || ?1 || '%' ORDER BY name")?;
        let rows = stmt.query_map(params![pat], |r| r.get::<_, String>(0))?;
        for res in rows { println!("{}", res?); }
        return Ok(());
    }

    if args.count {
        let conn = conn.lock().await;
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM domains", [], |r| r.get(0))?;
        println!("📊 Total de subdomínios: {}", total);
        return Ok(());
    }

    if let Some(mass_scan_file) = args.mass_scan {
        if std::env::var("TMUX").is_err() {
            let session_name = "monrust_mass_scan";
            let exe_path = std::env::current_exe()?;

            // Comando corrigido: loop infinito para manter o tmux aberto
            let cmd = format!(
                "tmux new-session -d -s {} 'while true; do {} --mass-scan {}; sleep 600; done'",
                session_name,
                exe_path.display(),
                mass_scan_file
            );

            let status = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .status()
                .await?;

            if status.success() {
                println!("🆕 Sessão tmux '{}' criada com sucesso!", session_name);
                println!("🔍 Use 'tmux attach -t {}' para acompanhar", session_name);
                return Ok(());
            } else {
                eprintln!("⚠️ Falha ao criar sessão tmux. Continuando na sessão atual...");
            }
        }

        println!("🚀 Iniciando escaneamento em massa de: {}", mass_scan_file);
        let contents = fs::read_to_string(&mass_scan_file)?;
        let domains: Vec<String> = contents.lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if domains.is_empty() {
            eprintln!("❌ Arquivo vazio ou sem domínios válidos");
            return Ok(());
        }

        println!("🔍 {} domínios para escanear", domains.len());
        
        let mut tasks = FuturesUnordered::new();
        let scan_sem = Arc::new(Semaphore::new(DEFAULT_THREADS));
        let task_semaphore = Arc::new(Semaphore::new(5)); // Máximo de 5 tarefas simultâneas

        for domain in domains {
            let conn = Arc::clone(&conn);
            let scan_sem = scan_sem.clone();
            let task_semaphore = task_semaphore.clone();
            let output_dir = output_dir.to_string();
            
            tasks.push(tokio::spawn(async move {
                let _permit = task_semaphore.acquire().await;
                let _permit2 = scan_sem.acquire().await;
                monitor_domain_internal(&domain, conn, DEFAULT_THREADS, 0, &output_dir).await
            }));
        }

        while let Some(result) = tasks.next().await {
            if let Err(e) = result {
                eprintln!("❌ Erro na task: {}", e);
            }
        }

        return Ok(());
    }

    if let Some(domain) = args.domain {
        let threads = std::cmp::min(DEFAULT_THREADS, 20);
        monitor_domain(&domain, conn, threads, scan_interval, output_dir).await?;
    }

    Ok(())
}

async fn download_wordlist(filename: &str, url: &str) -> anyhow::Result<()> {
    if !Path::new(filename).exists() {
        println!("⬇️ Baixando wordlist: {}", filename);
        let status = Command::new("curl")
            .arg("-s")
            .arg("-o")
            .arg(filename)
            .arg(url)
            .status()
            .await?;
        
        if !status.success() {
            return Err(anyhow!("Falha ao baixar wordlist: {}", filename));
        }
        println!("✅ Wordlist baixada: {}", filename);
        
        let metadata = fs::metadata(filename)?;
        if metadata.len() == 0 {
            return Err(anyhow!("Arquivo wordlist vazio: {}", filename));
        }
    }
    Ok(())
}

async fn monitor_domain(
    domain: &str,
    conn: Arc<Mutex<Connection>>,
    threads: usize,
    scan_interval: u64,
    output_dir: &str,
) -> anyhow::Result<()> {
    if std::env::var("TMUX").is_err() {
        let session_name = format!("monrust_{}", domain.replace('.', "_"));
        let exe_path = std::env::current_exe()?;

        // Comando corrigido: loop infinito para manter o tmux aberto
        let cmd = format!(
            "tmux new-session -d -s {} 'while true; do {} -d {}; sleep {}; done'",
            session_name,
            exe_path.display(),
            domain,
            scan_interval * 60
        );

        let status = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status()
            .await?;

        if status.success() {
            println!("🆕 Sessão tmux '{}' criada com sucesso!", session_name);
            println!("🔍 Use 'tmux attach -t {}' para acompanhar", session_name);
            return Ok(());
        } else {
            eprintln!("⚠️ Falha ao criar sessão tmux. Continuando na sessão atual...");
        }
    }

    monitor_domain_internal(domain, conn, threads, scan_interval, output_dir).await
}

async fn monitor_domain_internal(
    domain: &str,
    conn: Arc<Mutex<Connection>>,
    threads: usize,
    scan_interval: u64,
    output_dir: &str,
) -> anyhow::Result<()> {
    println!("🔄 Iniciando monitoramento para: {}", domain);

    if scan_interval == 0 {
        println!("🚀 Execução única para: {}", domain);
        process_scan_cycle(&domain, &conn, threads, output_dir).await?;
        return Ok(());
    }

    let mut ticker = interval(Duration::from_secs(scan_interval * 60));

    loop {
        ticker.tick().await;
        println!("⏳ Verificando novos subdomínios para {}...", domain);
        process_scan_cycle(&domain, &conn, threads, output_dir).await?;
    }
}

// Função para extrair palavras do robots.txt
async fn extract_words_from_robots(domain: &str) -> anyhow::Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    let robots_urls = [
        format!("https://{}/robots.txt", domain),
        format!("http://{}/robots.txt", domain),
    ];

    for url in &robots_urls {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let content = resp.text().await?;
                println!("✅ Robots.txt encontrado para: {}", domain);
                
                // Extrair caminhos do robots.txt
                let path_re = Regex::new(r"(?i)(?:Allow|Disallow):\s*(/\S*)")?;
                let mut paths = Vec::new();
                
                for cap in path_re.captures_iter(&content) {
                    if let Some(path) = cap.get(1) {
                        paths.push(path.as_str().to_string());
                    }
                }
                
                // Extrair palavras dos caminhos
                let word_re = Regex::new(r"[\w-]{3,}")?;
                let mut words = HashSet::new();
                
                for path in paths {
                    for cap in word_re.captures_iter(&path) {
                        if let Some(word) = cap.get(0) {
                            let word = word.as_str().to_lowercase();
                            words.insert(word);
                        }
                    }
                }
                
                if words.is_empty() {
                    println!("ℹ️ Nenhuma palavra extraída do robots.txt");
                    return Ok(Vec::new());
                }
                
                println!("📝 {} palavras extraídas do robots.txt", words.len());
                return Ok(words.into_iter().collect());
            }
            _ => continue,
        }
    }
    
    println!("ℹ️ Robots.txt não encontrado para: {}", domain);
    Ok(Vec::new())
}

// Função para adicionar palavras às wordlists
async fn add_words_to_wordlists(words: &[String]) -> anyhow::Result<()> {
    if words.is_empty() {
        return Ok(());
    }

    for &wordlist in &["general_wordlist.txt", "api_wordlist.txt"] {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(wordlist)
            .await?;

        for word in words {
            file.write_all(word.as_bytes()).await?;
            file.write_all(b"\n").await?;
        }
    }

    println!("✅ Palavras adicionadas às wordlists");
    Ok(())
}

async fn process_scan_cycle(
    domain: &str,
    conn: &Arc<Mutex<Connection>>,
    threads: usize,
    output_dir: &str,
) -> anyhow::Result<()> {
    println!("🌐 Enumerando subdomínios para: {}", domain);
    let current_domains = match enum_subdomains(&domain).await {
        Ok(subs) => {
            if subs.is_empty() {
                println!("ℹ️ Nenhum subdomínio encontrado para {}", domain);
            } else {
                println!("✅ {} subdomínios encontrados para {}", subs.len(), domain);
            }
            subs
        },
        Err(e) => {
            eprintln!("❌ Erro ao enumerar subdomínios: {}", e);
            return Ok(());
        }
    };

    let known = {
        let conn = conn.lock().await;
        get_known(&conn)?
    };

    let new: HashSet<_> = current_domains.difference(&known).cloned().collect();
    
    if new.is_empty() {
        println!("⏭️ Nenhum novo subdomínio encontrado para {} em {}", domain, Local::now());
        return Ok(());
    }

    println!("🎯 {} novos subdomínios encontrados para {}!", new.len(), domain);
    
    if new.len() > 10 {
        let message = format!(
            "🎯 *{} novos subdomínios* encontrados para {}!\n\nLista completa disponível no banco de dados.",
            new.len(), domain
        );
        alert_telegram("Descoberta de Subdomínios", &message).await?;
    } else {
        let new_subs_list = new.iter().map(|s| format!("• {}", s)).collect::<Vec<_>>().join("\n");
        let message = format!(
            "🎯 *{} novos subdomínios* encontrados para {}!\n\n{}\n\n🔄 Iniciando escaneamento...",
            new.len(), domain, new_subs_list
        );
        alert_telegram("Descoberta de Subdomínios", &message).await?;
    }

    {
        let conn = conn.lock().await;
        for sub in &new {
            match conn.execute(
                "INSERT OR IGNORE INTO domains (name, seen_at, processed) VALUES (?1, ?2, 0)",
                params![sub, Local::now().to_rfc3339()],
            ) {
                Ok(1) => println!("✅ Subdomínio adicionado ao banco: {}", sub),
                Ok(0) => println!("ℹ️ Subdomínio já existente: {}", sub),
                Ok(_) => (),
                Err(e) => eprintln!("❌ Erro ao inserir subdomínio '{}': {}", sub, e),
            }
        }
    }

    let task_semaphore = Arc::new(Semaphore::new(5)); // Máximo de 5 tarefas simultâneas
    let mut tasks: FuturesUnordered<tokio::task::JoinHandle<()>> = FuturesUnordered::new();

    for new_domain in new {
        let conn = Arc::clone(conn);
        let task_semaphore = task_semaphore.clone();
        let output_dir = output_dir.to_string();
        
        tasks.push(tokio::spawn(async move {
            // Adquirir permissão do semáforo
            let _permit = match task_semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            println!("🔍 Iniciando escaneamento para: {}", new_domain);
            
            // Extrair palavras do robots.txt e adicionar às wordlists
            match extract_words_from_robots(&new_domain).await {
                Ok(words) => {
                    if let Err(e) = add_words_to_wordlists(&words).await {
                        eprintln!("⚠️ Falha ao adicionar palavras: {}", e);
                    }
                }
                Err(e) => eprintln!("⚠️ Falha ao extrair robots.txt: {}", e),
            }
            
            let needs_processing = {
                let conn = conn.lock().await;
                let mut stmt = match conn.prepare("SELECT processed FROM domains WHERE name = ?1") {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        eprintln!("❌ Erro ao preparar consulta: {}", e);
                        return;
                    }
                };
                
                match stmt.query_row(params![&new_domain], |row| row.get::<_, bool>(0)) {
                    Ok(processed) => !processed,
                    Err(_) => true // Não encontrado, precisa processar
                }
            };

            if !needs_processing {
                println!("ℹ️ Subdomínio {} já processado. Pulando.", new_domain);
                return;
            }

            let active_urls = match run_httpx(&new_domain).await {
                Ok(urls) => urls,
                Err(e) => {
                    eprintln!("❌ Erro no httpx: {}", e);
                    vec![]
                }
            };

            let urls_to_scan = if active_urls.is_empty() {
                println!("⚠️ Nenhuma URL ativa encontrada, tentando fallback para: {}", new_domain);
                vec![new_domain.to_string()]
            } else {
                active_urls
            };

            let mut ferox_discovered_urls = Vec::new();
            let mut ferox_found_something = false;

            for url in &urls_to_scan {
                match run_feroxbuster(url, threads, &output_dir, &new_domain).await {
                    Ok(urls) => {
                        if !urls.is_empty() {
                            ferox_found_something = true;
                            let message = format!(
                                "🚀 *URLs descobertas* em {}\n\n{}",
                                url,
                                urls.iter().take(10).map(|u| format!("• {}", u)).collect::<Vec<_>>().join("\n")
                            );
                            if urls.len() > 10 {
                                alert_telegram("Descoberta de URLs", &format!("{} e mais {} URLs", message, urls.len()-10)).await.ok();
                            } else {
                                alert_telegram("Descoberta de URLs", &message).await.ok();
                            }
                            ferox_discovered_urls.extend(urls);
                        }
                    }
                    Err(e) => eprintln!("❌ Feroxbuster falhou em {}: {}", url, e),
                }
            }

            // Se o Feroxbuster não encontrou nada, rodar o Nuclei diretamente
            if !ferox_found_something {
                println!("ℹ️ Feroxbuster não encontrou URLs, rodando Nuclei diretamente...");
                if let Err(e) = run_nuclei(&urls_to_scan, &new_domain, &conn, &output_dir).await {
                    eprintln!("❌ Nuclei falhou em {}: {}", new_domain, e);
                }
            } else {
                if let Err(e) = run_nuclei(&ferox_discovered_urls, &new_domain, &conn, &output_dir).await {
                    eprintln!("❌ Nuclei falhou em {}: {}", new_domain, e);
                }
            }

            let conn = conn.lock().await;
            if let Err(e) = conn.execute(
                "UPDATE domains SET processed = 1 WHERE name = ?1",
                params![&new_domain],
            ) {
                eprintln!("❌ Erro ao atualizar banco: {}", e);
            } else {
                println!("✅ Subdomínio marcado como processado: {}", new_domain);
            }
        }));
    }

    // Aguarda todas as tasks terminarem antes de retornar
    while let Some(result) = tasks.next().await {
        if let Err(e) = result {
            eprintln!("❌ Erro na task de escaneamento: {}", e);
        }
    }

    Ok(())
}

async fn run_httpx(domain: &str) -> anyhow::Result<Vec<String>> {
    println!("🌐 Verificando URLs ativas para: {}", domain);
    
    let output = Command::new("httpx")
        .args(&[
            "-target", domain,
            "-ports", TOP_1000_PORTS,
            "-silent",
            "-status-code",
            "-content-length",
            "-title"
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("httpx falhou: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    if stdout.is_empty() {
        println!("ℹ️ Nenhuma URL ativa encontrada para: {}", domain);
        return Ok(Vec::new());
    }

    let active_urls: Vec<String> = stdout.lines()
        .map(|line| line.split_whitespace().next().unwrap_or("").to_string())
        .filter(|url| !url.is_empty())
        .collect();

    println!("✅ {} URLs ativas encontradas", active_urls.len());
    Ok(active_urls)
}

async fn run_feroxbuster(url: &str, threads: usize, output_dir: &str, domain: &str) -> anyhow::Result<Vec<String>> {
    println!("⚡ Executando Feroxbuster em: {}", url);
    
    let wordlist = if url.contains("api") || url.contains("dev") || 
                   url.contains("prod") || url.contains("prd") 
    {
        "api_wordlist.txt"
    } else {
        "general_wordlist.txt"
    };
    
    if !Path::new(wordlist).exists() {
        return Err(anyhow!("Wordlist não encontrada: {}", wordlist));
    }
    let metadata = fs::metadata(wordlist)?;
    if metadata.len() == 0 {
        return Err(anyhow!("Wordlist vazia: {}", wordlist));
    }
    
    // Usar diretório único para todos os resultados
    fs::create_dir_all(output_dir)?;
    
    // Nome do arquivo de saída inclui o domínio para evitar conflitos
    let output_file = format!("{}/feroxresults_{}.json", output_dir, sanitize_filename(domain));
    
    // Sistema de retentativas com timeout
    let mut attempts = 0;
    let max_attempts = 3;
    
    while attempts < max_attempts {
        attempts += 1;
        println!("🔁 Tentativa {}/{} para Feroxbuster", attempts, max_attempts);
        
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            Command::new("feroxbuster")
                .args(&[
                    "--url", url,
                    "--wordlist", wordlist,
                    "--threads", &threads.to_string(),
                    "--collect-backups",
                    "--collect-extensions",
                    "--collect-words",
                    "--force-recursion",
                    "--no-state",
                    "--timeout", "20",
                    "--depth", "3",
                    "--random-agent",
                    "--insecure",
                    "--silent",
                    "--status-codes", "200",
                    "--dont-collect", "jpg,jpeg,png,gif,ico,bmp,svg,webp,tiff,woff,woff2,ttf,eot",
                    "--output", &output_file,
                ])
                .status()
        ).await;
        
        match result {
            Ok(Ok(status)) if status.success() => break,
            _ => {
                if attempts < max_attempts {
                    println!("⏱️ Aguardando 10 segundos antes de tentar novamente...");
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }
    }

    // Se o arquivo estiver vazio, retorna lista vazia
    if let Ok(metadata) = fs::metadata(&output_file) {
        if metadata.len() == 0 {
            println!("ℹ️ Feroxbuster não encontrou resultados");
            return Ok(Vec::new());
        }
    } else {
        println!("⚠️ Feroxbuster não gerou arquivo de saída");
        return Ok(Vec::new());
    }

    // Lê o arquivo de saída e extrai URLs
    let content = match fs::read_to_string(&output_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("⚠️ Falha ao ler arquivo de saída: {}", e);
            return Ok(Vec::new());
        }
    };

    let urls: Vec<String> = content.lines()
        .filter_map(|line| {
            if line.contains("\"url\":") {
                line.split(':')
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join(":")
                    .trim_matches(|c| c == '"' || c == ',' || c == ' ')
                    .to_string()
                    .into()
            } else {
                None
            }
        })
        .collect();

    println!("✅ Feroxbuster encontrou {} URLs", urls.len());
    Ok(urls)
}

fn sanitize_filename(input: &str) -> String {
    input.replace(|c: char| !c.is_alphanumeric(), "_")
}

async fn run_nuclei(
    urls: &[String],
    domain: &str,
    conn: &Arc<Mutex<Connection>>,
    output_dir: &str,
) -> anyhow::Result<()> {
    println!("🔬 Executando Nuclei em: {}", domain);
    
    if urls.is_empty() {
        println!("ℹ️ Nenhuma URL para escanear");
        return Ok(());
    }
    
    // Usar diretório único para todos os resultados
    fs::create_dir_all(output_dir)?;
    
    // Arquivo temporário de entrada
    let temp_file = format!("{}/nuclei_input_{}.txt", output_dir, sanitize_filename(domain));
    fs::write(&temp_file, urls.join("\n"))?;
    
    // Arquivo de resultados inclui o domínio para evitar conflitos
    let output_file = format!("{}/nuclei_{}.txt", output_dir, sanitize_filename(domain));
    
    // Executa o Nuclei e salva em modo append
    let output = Command::new("nuclei")
        .args(&[
            "-list", &temp_file,
            "-severity", DEFAULT_SEVERITY,
            "-tags", "xss,rce,ssrf,misconfig",
            "-etags", "info",
            "-follow-redirects",
            "-concurrency", "20",
            "-no-color",
        ])
        .output()
        .await?;

    // Remove arquivo temporário
    fs::remove_file(&temp_file)?;

    // Processa a saída do Nuclei
    let body = String::from_utf8_lossy(&output.stdout).to_string();
    
    if body.is_empty() {
        println!("ℹ️ Nuclei não encontrou vulnerabilidades");
        return Ok(());
    }

    println!("⚠️ Vulnerabilidades encontradas!\n{}", body);
    
    // Salva em arquivo com nome único
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output_file)
        .await?;
    
    file.write_all(body.as_bytes()).await?;
    file.write_all(b"\n").await?;

    // Salva no banco de dados
    let conn = conn.lock().await;
    conn.execute(
        "INSERT OR REPLACE INTO scan_results (domain, nuclei_data, scanned_at) VALUES (?1, ?2, ?3)",
        params![domain, body, Local::now().to_rfc3339()],
    )?;
    
    // Formatar saída do Nuclei para Telegram
    let message = format!(
        "🚨 *VULNERABILIDADES ENCONTRADAS* em {}\n\n{}\n",
        domain, body
    );
    alert_telegram("Vulnerabilidades Detectadas", &message).await?;
    
    Ok(())
}

async fn alert_telegram(title: &str, message: &str) -> anyhow::Result<()> {
    let token = "7855940469:AAH1JBuBEr1y__bt7LjLf1NGFvP7TU7XKyY";
    let chat_id = "215999042";
    
    // Limitar o tamanho da mensagem
    let max_length = 4000;
    let truncated_msg = if message.len() > max_length {
        &message[..max_length]
    } else {
        message
    };
    
    let text = format!("🛡️ *{}*\n\n{}", title, truncated_msg);
    let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
    
    let max_retries = 3;
    let mut retry_count = 0;
    
    loop {
        let response = reqwest::Client::new()
            .post(&url)
            .form(&[
                ("chat_id", chat_id),
                ("text", &text),
                ("parse_mode", "Markdown"),
                ("disable_web_page_preview", "true")
            ])
            .send()
            .await?;
    
        let status = response.status().as_u16();
        let body = response.text().await?;
        
        if status == 200 {
            return Ok(());
        }
        
        if status == 429 {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(retry_after) = json["parameters"]["retry_after"].as_u64() {
                    if retry_count < max_retries {
                        retry_count += 1;
                        eprintln!("⚠️ Limite do Telegram excedido. Tentando novamente em {} segundos", retry_after);
                        sleep(Duration::from_secs(retry_after)).await;
                        continue;
                    }
                }
            }
        }
        
        return Err(anyhow!("Falha no Telegram ({}) {}", status, body));
    }
}

async fn enum_subdomains(domain: &str) -> anyhow::Result<HashSet<String>> {
    println!("🌐 Enumerando subdomínios para: {}", domain);
    let output = Command::new("subfinder")
        .args(&["-d", domain, "-all", "-silent"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Subfinder falhou: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let set: HashSet<String> = stdout.lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    if set.is_empty() {
        println!("ℹ️ Nenhum subdomínio encontrado");
    } else {
        println!("✅ {} subdomínios encontrados", set.len());
    }
    
    Ok(set)
}

fn get_known(conn: &Connection) -> rusqlite::Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT name FROM domains")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut set = HashSet::new();
    for res in rows { 
        if let Ok(name) = res {
            set.insert(name); 
        }
    }
    Ok(set)
}

fn init_db() -> rusqlite::Result<Connection> {
    let first = !Path::new(DB_FILE).exists();
    let conn = Connection::open(DB_FILE)?;
    if first {
        conn.execute(
            "CREATE TABLE domains (name TEXT PRIMARY KEY, seen_at TEXT, processed BOOLEAN DEFAULT 0)",
            [],
        )?;
        conn.execute(
            "CREATE TABLE scan_results (
                domain TEXT PRIMARY KEY,
                nuclei_data TEXT,
                scanned_at TEXT
            )",
            [],
        )?;
        println!("✅ Banco de dados inicializado");
    } else {
        let _ = conn.execute(
            "ALTER TABLE domains ADD COLUMN processed BOOLEAN DEFAULT 0",
            [],
        );
    }
    Ok(conn)
}
