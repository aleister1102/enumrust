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
use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{info, warn};
use tokio;
use futures::future::join_all;

/// Subdomain enumerator and simple crawler with port scanning
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Target domain to enumerate
    #[arg(short, long)]
    domain: Option<String>,
    
    /// File containing list of domains to enumerate
    #[arg(short, long)]
    list: Option<String>,
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

fn brute_force_vhosts(domain: &str, base: &Path) -> Result<()> {
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

fn parse_feroxbuster_results(ferox_output: &Path, base: &Path) -> Result<()> {
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
                            let blacklist = [".png", ".ico", ".jpeg", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".css"];
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

fn run_nuclei_scan(input_file: &Path, base: &Path) -> Result<()> {
    let nuclei_output = base.join("nuclei_results.txt");
    
    println!("\n{} Running Nuclei scan on consolidated URLs", "⚡".yellow());
    println!("{} Input file: {}", "•".blue(), input_file.display());
    
    let status = Command::new("nuclei")
        .args(&[
            "-l", input_file.to_str().unwrap(),
            "-etags", "ssl",
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
        // Skip common framework parameters that aren't interesting
        if name.contains("__") || name == "csrf" || name == "token" || name == "session" {
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

fn fetch_robots_paths(domain: &str) -> Result<Vec<String>> {
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

fn add_words_to_wordlists(paths: &[String], wordlist_path: &Path) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(wordlist_path)?;

    for path in paths {
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

fn run_feroxbuster_with_timeout(
    combined_targets: &Path,
    wordlist_path: &Path,
    ferox_output: &Path,
) -> Result<()> {
    println!("[*] Running feroxbuster with 1-minute timeout...");
    
    let start_time = Instant::now();
    let timeout_duration = Duration::from_secs(60);
    
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
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Error waiting for feroxbuster: {}", e);
                return Err(e.into());
            }
        }
    }
    
    println!("{} Feroxbuster timed out after 1 minute", "⌛".yellow());
    cmd.kill()?;
    cmd.wait()?;
    println!("[*] Proceeding to Nuclei scan immediately");
    
    Ok(())
}

async fn process_domain(domain: &str) -> Result<()> {
    info!("Starting enumeration for domain: {}", domain);

    // Create progress bars
    let multi = MultiProgress::new();
    let progress_style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .unwrap();

    let pb = multi.add(ProgressBar::new_spinner());
    pb.set_style(progress_style.clone());
    pb.set_message("Initializing...");
    fs::create_dir_all(domain).context("Failed to create directory")?;
    let base = Path::new(domain);

    pb.set_message("Brute forcing vhosts...");
    if let Err(e) = brute_force_vhosts(domain, base) {
        warn!("Vhost enumeration failed: {}", e);
    }

    let subs_txt = base.join("subdomains.txt");
    pb.set_message("Enumerating subdomains via subfinder...");
    
    let subfinder_output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "subfinder -silent -all -d {} | anew {}",
            domain,
            subs_txt.display()
        ))
        .output()
        .context("Failed to run subfinder")?;

    if !subfinder_output.status.success() {
        warn!("Subfinder failed: {}", String::from_utf8_lossy(&subfinder_output.stderr));
    }

    pb.set_message("Extracting certificate SANs with tlsx...");
    let tlsx_output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {} | tlsx -json -silent | jq -r '.subject_an[] | ltrimstr(\"*.\")' | anew {}",
            domain,
            subs_txt.display()
        ))
        .output()
        .context("Failed to run tlsx")?;

    if !tlsx_output.status.success() {
        warn!("TLSX failed: {}", String::from_utf8_lossy(&tlsx_output.stderr));
    }

    let ips_txt = base.join("ips.txt");
    pb.set_message("Resolving subdomains to IPs with dnsx...");
    let dnsx_output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | dnsx -a -resp-only -silent -o {}",
            subs_txt.display(),
            ips_txt.display()
        ))
        .output()
        .context("Failed to run dnsx")?;

    if !dnsx_output.status.success() {
        warn!("DNSX failed: {}", String::from_utf8_lossy(&dnsx_output.stderr));
    }

    let masscan_txt = base.join("masscan.txt");
    pb.set_message("Scanning ports with masscan...");
    let masscan_output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "masscan -iL {} --ports 1-65535 --rate 10000 -oL {}",
            ips_txt.display(),
            masscan_txt.display()
        ))
        .output()
        .context("Failed to run masscan")?;

    if !masscan_output.status.success() {
        warn!("Masscan failed: {}", String::from_utf8_lossy(&masscan_output.stderr));
    }

    let ports_txt = base.join("ports.txt");
    pb.set_message("Validating open ports with httpx...");
    let httpx_ports_output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | awk '/open/ {{print $4 \":\" $3}}' | httpx -silent -o {}",
            masscan_txt.display(),
            ports_txt.display()
        ))
        .output()
        .context("Failed to run httpx for ports")?;

    if !httpx_ports_output.status.success() {
        warn!("HTTPX ports scan failed: {}", String::from_utf8_lossy(&httpx_ports_output.stderr));
    }

    let http200_txt = base.join("http200.txt");
    pb.set_message("Resolving hosts with httpx...");
    let httpx_hosts_output = Command::new("httpx")
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
        .output()
        .context("Failed to run httpx for hosts")?;

    if !httpx_hosts_output.status.success() {
        warn!("HTTPX hosts scan failed: {}", String::from_utf8_lossy(&httpx_hosts_output.stderr));
    }

    let mut cloud_buckets_file = File::create(base.join("cloud_buckets.txt"))?;
    let mut urls_file = File::create(base.join("urls.txt"))?;
    let mut hidden_file = File::create(base.join("hiddenparams.txt"))?;

    let cloud_regexes = vec![
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-\.]+\.s3\.amazonaws\.com)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])(s3-[a-z0-9\-]+\.amazonaws\.com/[a-z0-9\-]+)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])(s3\.[a-z0-9\-]+\.amazonaws\.com/[a-z0-9\-]+)").unwrap(),
        Regex::new(r"(?:^|[^a-z0-9])([a-z0-9\-]+\.s3-website[\.\.-](?:eu|ap|us|sa|ca|af|me|cn)[\-][a-z0-9\-]+\.amazonaws\.com(?:[/\.].*)?)").unwrap(),
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

    pb.set_message("Crawling URLs and scanning for cloud resources...");
    let file = File::open(&http200_txt).context("Failed to open http200.txt")?;
    let lines: Vec<String> = BufReader::new(file).lines().collect::<Result<_, _>>()?;
    
    let progress_bar = ProgressBar::new(lines.len() as u64);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .unwrap());

    for url in lines {
        progress_bar.set_message(format!("Crawling: {}", url));
        match client.get(&url).send().and_then(|r| r.text()) {
            Ok(body) => {
                let document = Html::parse_document(&body);
                
                // Scan for cloud buckets
                for regex in &cloud_regexes {
                    for cap in regex.captures_iter(&body) {
                        if let Some(bucket) = cap.get(1) {
                            let bucket_str = bucket.as_str().trim_matches(|c| c == '\'' || c == '"' || c == '\\');
                            if seen_buckets.insert(bucket_str.to_string()) {
                                if let Err(e) = writeln!(cloud_buckets_file, "{}", bucket_str) {
                                    warn!("Failed to write cloud bucket to file: {}", e);
                                } else {
                                    info!("Found cloud bucket: {}", bucket_str);
                                    progress_bar.println(format!("{} Found cloud bucket: {}", "✔".green(), bucket_str.green()));
                                }
                            }
                        }
                    }
                }
                
                // Extract URLs from href attributes
                if let Ok(sel) = Selector::parse("a[href]") {
                    for elem in document.select(&sel) {
                        if let Some(href) = elem.value().attr("href") {
                            if href.contains(domain) && seen_urls.insert(href.to_string()) {
                                if let Err(e) = writeln!(urls_file, "{}", href) {
                                    warn!("Failed to write URL to file: {}", e);
                                } else {
                                    info!("Found URL: {}", href);
                                }
                            }
                        }
                    }
                } else {
                    warn!("Failed to parse href selector");
                }
                
                // Extract URLs from HTML comments
                for caps in re_comments.captures_iter(&body) {
                    let comment_text = &caps[1];
                    for url_cap in re_comment_urls.find_iter(comment_text) {
                        let link = url_cap.as_str().trim_end_matches('"').to_string();
                        if link.contains(domain) && seen_urls.insert(link.clone()) {
                            if let Err(e) = writeln!(urls_file, "{}", link) {
                                warn!("Failed to write comment URL to file: {}", e);
                            } else {
                                info!("Found comment URL: {}", link);
                            }
                        }
                    }
                }
                
                // Extract hidden parameters
                if let Some(hurls) = extract_hidden_params(&url, &body, &re_hidden) {
                    for hurl in hurls {
                        if seen_hidden.insert(hurl.clone()) {
                            if let Err(e) = writeln!(hidden_file, "{}", hurl) {
                                warn!("Failed to write hidden parameter to file: {}", e);
                            } else {
                                info!("Found hidden parameter: {}", hurl);
                                progress_bar.println(format!("[+] Hidden param found: {}", hurl.blue()));
                            }
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    pb.set_message("Extracting parameters with hakrawler...");
    let hakrawler_output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | hakrawler -s href -subs | anew {}",
            http200_txt.display(),
            base.join("params.txt").display()
        ))
        .output()
        .context("Failed to run hakrawler")?;

    if !hakrawler_output.status.success() {
        warn!("Hakrawler failed: {}", String::from_utf8_lossy(&hakrawler_output.stderr));
    } else {
        info!("Successfully extracted parameters with hakrawler");
    }

    let wordlist_url = "https://raw.githubusercontent.com/onvio/wordlists/master/words_and_files_top5000.txt";
    let wordlist_path = base.join("wordlist.txt");

    if !wordlist_path.exists() {
        pb.set_message("Downloading wordlist...");
        let curl_output = Command::new("sh")
            .arg("-c")
            .arg(format!("curl -s -o {} {}", wordlist_path.display(), wordlist_url))
            .output()
            .context("Failed to download wordlist")?;

        if !curl_output.status.success() {
            warn!("Failed to download wordlist: {}", String::from_utf8_lossy(&curl_output.stderr));
        } else {
            info!("Successfully downloaded wordlist");
        }
    }

    pb.set_message("Crawling robots.txt paths...");
    let paths = fetch_robots_paths(domain)?;
    if !paths.is_empty() {
        add_words_to_wordlists(&paths, &wordlist_path)?;
    }

    let combined_targets = base.join("combined_targets.txt");
    let mut combined_file = File::create(&combined_targets)?;

    // Combine targets from http200.txt, ports.txt, and params.txt
    for source in &[&http200_txt, &ports_txt, &base.join("params.txt")] {
        if source.exists() {
            if let Ok(content) = fs::read_to_string(source) {
                write!(combined_file, "{}", content)?;
            }
        }
    }

    let ferox_output = base.join("ferox_output.txt");
    run_feroxbuster_with_timeout(&combined_targets, &wordlist_path, &ferox_output)?;
    parse_feroxbuster_results(&ferox_output, base)?;

    // Consolidate final URLs for nuclei scan
    let final_urls = base.join("final_urls.txt");
    let mut final_file = File::create(&final_urls)?;

    for source in &[&http200_txt, &ports_txt, &base.join("params.txt"), &base.join("ferox_parsed.txt"), &base.join("hiddenparams.txt")] {
        if source.exists() {
            if let Ok(content) = fs::read_to_string(source) {
                write!(final_file, "{}", content)?;
            }
        }
    }

    run_nuclei_scan(&final_urls, base)?;
    pb.finish_with_message("Domain processing complete");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    validate_dependencies();

    match (args.domain, args.list) {
        (Some(domain), None) => {
            process_domain(&domain).await?
        },
        (None, Some(list_path)) => {
            let domains: Vec<String> = fs::read_to_string(list_path)?
                .lines()
                .map(String::from)
                .collect();
            
            let tasks: Vec<_> = domains.iter()
                .map(|domain| process_domain(domain))
                .collect();
            
            join_all(tasks).await;
        },
        _ => {
            eprintln!("Please provide either a domain (-d) or a list of domains (-l)");
            std::process::exit(1);
        }
    }

    Ok(())
}
