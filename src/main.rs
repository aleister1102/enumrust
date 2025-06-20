use clap::Parser;
use regex::Regex;
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use colored::*;

/// Subdomain enumerator and simple crawler with port scanning
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Target domain to enumerate
    #[arg(short, long)]
    domain: String,
}

fn validate_dependencies() {
    let tools = vec![
        "subfinder", "anew", "tlsx", "jq", "dnsx", "masscan", "httpx", "hakrawler",
        "nuclei", "curl", "feroxbuster", "ffuf"
    ];

    println!("\n🔍 Checking required tools:\n");
    for tool in tools {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {} > /dev/null", tool))
            .status()
            .expect("Failed to run shell");

        if status.success() {
            println!("✅ {} is installed", tool.green());
        } else {
            println!("❌ {} is missing", tool.red());
        }
    }
    println!("");
}

fn brute_force_vhosts(domain: &str, base: &Path) -> anyhow::Result<()> {
    let vhost_output = base.join("vhost_results.txt");
    
    if vhost_output.exists() {
        println!("[*] Vhost results already exist, skipping...");
        return Ok(());
    }

    let vhost_wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt";
    let vhost_wordlist_path = base.join("vhost_wordlist.txt");
    
    if !vhost_wordlist_path.exists() {
        println!("[*] Downloading vhost wordlist...");
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("curl -s -o {} {}", vhost_wordlist_path.display(), vhost_wordlist_url))
            .status()?;
    }

    println!("[*] Brute-forcing virtual hosts with ffuf...");
    
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ffuf -u http://{} -w {} -H \"Host: FUZZ.{}\" -mc all -fc 400-499 -o {} -of json -v",
            domain,
            vhost_wordlist_path.display(),
            domain,
            vhost_output.display()
        ))
        .status()?;

    if !status.success() {
        println!("{} Failed to run ffuf vhost scan", "✗".red());
        return Ok(());
    }

    if vhost_output.exists() {
        let contents = fs::read_to_string(&vhost_output)?;
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
            if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
                let mut found = false;
                for result in results {
                    if let (Some(url), Some(host)) = (result.get("url"), result.get("host")) {
                        let url_str = url.as_str().unwrap_or("");
                        let host_str = host.as_str().unwrap_or("");
                        if !host_str.is_empty() {
                            println!("{} Found vhost: {} at {}", "✔".green(), host_str.green(), url_str);
                            found = true;
                        }
                    }
                }
                if !found {
                    println!("{} No vhosts found", "✗".yellow());
                }
            }
        }
    }

    Ok(())
}

fn parse_feroxbuster_results(ferox_output: &Path, base: &Path) -> anyhow::Result<()> {
    let parsed_output = base.join("ferox_parsed.txt");
    let mut output_file = File::create(&parsed_output)?;
    
    if ferox_output.exists() {
        let contents = fs::read_to_string(ferox_output)?;
        
        // Feroxbuster 2.x+ outputs JSON lines format
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            // Skip configuration lines that start with {
            if line.trim().starts_with('{') && line.contains("Configuration") {
                continue;
            }
            
            // Try to parse as JSON only if it looks like a result line
            if line.contains("url") && line.contains("status") {
                match serde_json::from_str::<Value>(line) {
                    Ok(json) => {
                        if let (Some(url), Some(status), Some(word)) = (
                            json.get("url").and_then(|u| u.as_str()),
                            json.get("status").and_then(|s| s.as_u64()),
                            json.get("word").and_then(|w| w.as_str())
                        ) {
                            // Skip image and non-content extensions
                            let blacklist = [".png", ".ico", ".jpeg", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot"];
                            if !blacklist.iter().any(|ext| url.ends_with(ext)) {
                                writeln!(output_file, "{} [{}] - Found via: {}", url, status, word)?;
                            }
                        }
                    },
                    Err(e) => eprintln!("{} Failed to parse line: {} - {}", "✗".red(), line, e),
                }
            } else {
                // If not JSON, try to parse as simple output line
                if line.contains("200") && line.contains("GET") {
                    if let Some(url) = line.split_whitespace().nth(1) {
                        writeln!(output_file, "{}", url)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn run_nuclei_scan(http200_txt: &Path, base: &Path) -> anyhow::Result<()> {
    let nuclei_output = base.join("nuclei_results.txt");
    
    println!("\n{} Running Nuclei scan on all discovered URLs", "⚡".yellow());
    
    let status = Command::new("nuclei")
        .args(&[
            "-l", http200_txt.to_str().unwrap(),
            "-tags", "xss,rce,ssrf,keycloak,actuator,misconfig",
            "-etags", "ssl,info",
            "-follow-redirects",
            "-severity", "medium,high,critical",
            "-no-color",
            "-silent",
            "-o", nuclei_output.to_str().unwrap()
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !status.success() {
        println!("{} Nuclei scan completed with some errors", "⚠".yellow());
    } else {
        println!("{} Nuclei scan completed successfully", "✔".green());
    }

    Ok(())
}

fn extract_hidden_params(
    base_url: &str,
    html: &str,
    re_hidden: &Regex,
) -> Option<Vec<String>> {
    let mut params = Vec::new();
    for cap in re_hidden.captures_iter(html) {
        let name = cap[2].to_string();
        if name.contains("__") {
            continue;
        }
        params.push(format!("{}=enumrust", name));
    }
    if params.is_empty() {
        return None;
    }
    let sep = if base_url.contains('?') { "&" } else { "?" };
    let full = format!("{}{}{}", base_url, sep, params.join("&"));
    Some(vec![full])
}

// Função para buscar e analisar robots.txt
fn fetch_robots_paths(domain: &str) -> anyhow::Result<Vec<String>> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    let robots_urls = [
        format!("https://{}/robots.txt", domain),
        format!("http://{}/robots.txt", domain),
    ];

    for url in &robots_urls {
        match client.get(url).send() {
            Ok(resp) if resp.status().is_success() => {
                let content = resp.text()?;
                println!("✅ {} Found robots.txt for {}", "✔".green(), domain);
                
                // Extrair caminhos do robots.txt
                let path_re = Regex::new(r"(?i)(?:Allow|Disallow):\s*(/\S*)")?;
                let mut paths = Vec::new();
                
                for cap in path_re.captures_iter(&content) {
                    if let Some(path) = cap.get(1) {
                        let path_str = path.as_str().to_string();
                        println!("   🛣️ {}", path_str.blue());
                        paths.push(path_str);
                    }
                }
                
                return Ok(paths);
            }
            _ => continue,
        }
    }
    
    println!("ℹ️ No robots.txt found for {}", domain);
    Ok(Vec::new())
}

// Função para adicionar palavras às wordlists
fn add_words_to_wordlists(paths: &[String], wordlist_path: &Path) -> anyhow::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(wordlist_path)?;

    for path in paths {
        // Extrair palavras dos caminhos
        let word_re = Regex::new(r"[\w-]{3,}")?;
        for cap in word_re.captures_iter(path) {
            if let Some(word) = cap.get(0) {
                let word = word.as_str().to_lowercase();
                writeln!(file, "{}", word)?;
                println!("   📝 Added to wordlist: {}", word.green());
            }
        }
    }

    println!("✅ Added {} paths to wordlist", paths.len());
    Ok(())
}

// Função para executar o feroxbuster com timeout de 1 minuto
fn run_feroxbuster_with_timeout(
    combined_targets: &Path,
    wordlist_path: &Path,
    ferox_output: &Path,
) -> anyhow::Result<()> {
    println!("[*] Running feroxbuster with 1-minute timeout...");
    
    let start_time = Instant::now();
    let timeout_duration = Duration::from_secs(60); // 1 minuto
    
    let mut cmd = Command::new("feroxbuster")
        .args(&[
            "--stdin",
            "--wordlist", wordlist_path.to_str().unwrap(),
            "--threads", "100",
            "--auto-tune",
            "--dont-collect", "jpg,jpeg,png,gif,ico,bmp,svg,webp,tiff,woff,woff2,ttf,eot",
            "--depth", "5",
            "--insecure",
            "--silent",
            "--random-agent",
            "--status-codes", "200",
            "--collect-backups",
            "--collect-extensions",
            "--scan-limit", "10",
            "--output", ferox_output.to_str().unwrap()
        ])
        .stdin(File::open(combined_targets)?)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    
    // Verifica periodicamente se o tempo expirou
    while start_time.elapsed() < timeout_duration {
        match cmd.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    println!("{} Feroxbuster completed successfully", "✔".green());
                } else {
                    println!("{} Feroxbuster completed with errors", "⚠".yellow());
                }
                return Ok(());
            }
            Ok(None) => {
                // Ainda está rodando, espera um pouco
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Error waiting for feroxbuster: {}", e);
                return Err(e.into());
            }
        }
    }
    
    // Timeout atingido
    println!("{} Feroxbuster timed out after 1 minute", "⌛".yellow());
    cmd.kill()?;
    cmd.wait()?; // Limpa o processo
    println!("[*] Proceeding to Nuclei scan immediately");
    
    Ok(())
}

fn main() -> anyhow::Result<()> {
    validate_dependencies();
    let args = Args::parse();
    let domain = &args.domain;
    fs::create_dir_all(domain)?;
    let base = Path::new(domain);

    brute_force_vhosts(domain, base)?;

    let subs_txt = base.join("subdomains.txt");
    println!("[*] Enumerating subdomains via subfinder...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "subfinder -silent -all -d {} | anew {}",
            domain,
            subs_txt.display()
        ))
        .status()?;

    println!("[*] Extracting certificate SANs with tlsx...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {} | tlsx -json -silent | jq -r '.subject_an[] | ltrimstr(\"*.\")' | anew {}",
            domain,
            subs_txt.display()
        ))
        .status()?;

    let ips_txt = base.join("ips.txt");
    println!("[*] Resolving subdomains to IPs with dnsx...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | dnsx -a -resp-only -silent -o {}",
            subs_txt.display(),
            ips_txt.display()
        ))
        .status()?;

    let masscan_txt = base.join("masscan.txt");
    println!("[*] Scanning ports with masscan...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "masscan -iL {} --ports 1-65535 --rate 10000 -oL {}",
            ips_txt.display(),
            masscan_txt.display()
        ))
        .status()?;

    let ports_txt = base.join("ports.txt");
    println!("[*] Validating open ports with httpx...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | awk '/open/ {{print $4 \":\" $3}}' | httpx -silent -o {}",
            masscan_txt.display(),
            ports_txt.display()
        ))
        .status()?;

    let http200_txt = base.join("http200.txt");
    println!("[*] Resolving hosts with httpx...");
    Command::new("httpx")
        .args(&[
            "-silent",
            "-follow-redirects",
            "-max-redirects",
            "10",
            "-list",
            &subs_txt.to_string_lossy(),
            "-o",
            &http200_txt.to_string_lossy(),
        ])
        .status()?;

    let mut cloud_buckets_file = File::create(base.join("cloud_buckets.txt"))?;
    let mut urls_file = File::create(base.join("urls.txt"))?;
    let mut hidden_file = File::create(base.join("hiddenparams.txt"))?;

    // Cloud bucket regex patterns
    let cloud_regexes = vec![
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-\.]+\.s3\.amazonaws\.com)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])(s3-[a-z0-9\-]+\.amazonaws\.com/[a-z0-9\-]+)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])(s3\.[a-z0-9\-]+\.amazonaws\.com/[a-z0-9\-]+)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-]+\.s3-website[\.\-](?:eu|ap|us|sa|ca|af|me|cn)[\-][a-z0-9\-]+\.amazonaws\.com(?:[/\.].*)?)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-\.]+\.s3\.(?:[a-z0-9\-]+\.)?amazonaws\.com\.?[^a-z0-9\.])").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])(storage\.cloud\.google\.com/[a-z0-9\-_\.]+)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-\.]+\.storage\.googleapis\.com)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-_\.]+\.appspot\.com)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-]+\.blob\.core\.windows\.net)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-]+\.azurewebsites\.net)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-]+\.azure-api\.net)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-]+\.file\.core\.windows\.net)").unwrap(),
    ];

    let re_comment_urls = Regex::new(r#"https?://[^\"\s]+"#)?;
    let re_comments = Regex::new(r#"<!--([\s\S]*?)-->"#)?;
    let re_hidden = Regex::new(r#"<input[^>]+name=('?\"?)([^\"'>\s]+)(\"?'?)"#)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    let mut seen_buckets = HashSet::new();
    let mut seen_urls = HashSet::new();
    let mut seen_hidden = HashSet::new();

    let file = File::open(&http200_txt)?;
    for line in BufReader::new(file).lines() {
        let url = line?;
        println!("[+] Crawling: {}", url);
        if let Ok(resp) = client.get(&url).send() {
            if let Ok(body) = resp.text() {
                let document = Html::parse_document(&body);
                
                for regex in &cloud_regexes {
                    for cap in regex.captures_iter(&body) {
                        if let Some(bucket) = cap.get(1) {
                            let bucket_str = bucket.as_str().trim_matches(|c| c == '\'' || c == '"' || c == '\\');
                            if seen_buckets.insert(bucket_str.to_string()) {
                                writeln!(cloud_buckets_file, "{}", bucket_str)?;
                                println!("{} Found cloud bucket: {}", "✔".green(), bucket_str.green());
                            }
                        }
                    }
                }
                
                let sel = Selector::parse("a[href]").unwrap();
                for elem in document.select(&sel) {
                    if let Some(href) = elem.value().attr("href") {
                        if href.contains(domain) && seen_urls.insert(href.to_string()) {
                            writeln!(urls_file, "{}", href)?;
                        }
                    }
                }
                
                for caps in re_comments.captures_iter(&body) {
                    let comment_text = &caps[1];
                    for url_cap in re_comment_urls.find_iter(comment_text) {
                        let link = url_cap.as_str().trim_end_matches('"').to_string();
                        if link.contains(domain) && seen_urls.insert(link.clone()) {
                            writeln!(urls_file, "{}", link)?;
                        }
                    }
                }
                
                if let Some(hurls) = extract_hidden_params(&url, &body, &re_hidden) {
                    for hurl in hurls {
                        if seen_hidden.insert(hurl.clone()) {
                            writeln!(hidden_file, "{}", hurl)?;
                        }
                    }
                }
            }
        }
    }

    println!("[*] Extracting params with hakrawler...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | hakrawler -s href -subs | anew {}",
            http200_txt.display(),
            base.join("params.txt").display()
        ))
        .status()?;

    let wordlist_url = "https://raw.githubusercontent.com/onvio/wordlists/master/words_and_files_top5000.txt";
    let wordlist_path = base.join("wordlist.txt");

    if !wordlist_path.exists() {
        println!("[*] Downloading wordlist...");
        Command::new("sh")
            .arg("-c")
            .arg(format!("curl -s -o {} {}", wordlist_path.display(), wordlist_url))
            .status()?;
    }

    // Crawler de robots.txt para cada subdomínio
    println!("[*] Crawling robots.txt for all domains...");
    let subs_file = File::open(&subs_txt)?;
    let mut domains_processed = HashSet::new();
    
    for line in BufReader::new(subs_file).lines() {
        let domain = line?;
        if domains_processed.insert(domain.clone()) {
            println!("🔍 Checking robots.txt for: {}", domain);
            match fetch_robots_paths(&domain) {
                Ok(paths) => {
                    if !paths.is_empty() {
                        println!("   🎯 Found {} paths in robots.txt", paths.len());
                        if let Err(e) = add_words_to_wordlists(&paths, &wordlist_path) {
                            eprintln!("⚠️ Failed to add words to wordlist: {}", e);
                        }
                    }
                }
                Err(e) => eprintln!("⚠️ Failed to fetch robots.txt: {}", e),
            }
        }
    }

    // Feroxbuster on subdomains and ports
    let ferox_output = base.join("ferox_results.json");
    
    // Combine subdomains and ports into one file for feroxbuster
    let combined_targets = base.join("combined_targets.txt");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} {} | sort -u > {}",
            subs_txt.display(),
            ports_txt.display(),
            combined_targets.display()
        ))
        .status()?;
    
    // Execute Feroxbuster with timeout handling
    run_feroxbuster_with_timeout(&combined_targets, &wordlist_path, &ferox_output)?;

    // Parse Feroxbuster results (mesmo se timeout ocorrer)
    parse_feroxbuster_results(&ferox_output, base)?;

    // Run Nuclei scan on all discovered URLs
    run_nuclei_scan(&http200_txt, base)?;

    println!(
        "[*] Done. Results saved in \"{}\" directory. Files: subdomains.txt, masscan.txt, ports.txt, http200.txt, cloud_buckets.txt, urls.txt, hiddenparams.txt, params.txt, ferox_results.json, ferox_parsed.txt, nuclei_results.txt, vhost_results.txt",
        domain
    );
    
    Ok(())
}
