use clap::Parser;
use colored::*;
use rand::Rng;
use regex::Regex;
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::sync::mpsc;

/// Subdomain enumerator and simple crawler with port scanning
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Target domain to enumerate
    #[arg(short, long)]
    domain: Option<String>,

    /// File containing list of domains to enumerate (one per line)
    #[arg(short = 'f', long)]
    file: Option<String>,
}

fn print_banner() {
    println!(); // Espaço inicial
    
    let mut rng = rand::thread_rng();
    let colors = [
        "red", "green", "yellow", "blue", "magenta", "cyan", "bright_red", 
        "bright_green", "bright_yellow", "bright_blue", "bright_magenta", "bright_cyan"
    ];
    
    let banner_lines = [
        "    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗███████╗████████╗",
        "    ██╔════╝████╗  ██║██║   ██║████╗ ████║██╔══██╗██║   ██║██╔════╝╚══██╔══╝",
        "    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║██████╔╝██║   ██║███████╗   ██║   ",
        "    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║╚════██║   ██║   ",
        "    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║╚██████╔╝███████║   ██║   ",
        "    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ",
    ];
    
    for line in banner_lines.iter() {
        let color_index = rng.gen_range(0..colors.len());
        match colors[color_index] {
            "red" => println!("{}", line.red()),
            "green" => println!("{}", line.green()),
            "yellow" => println!("{}", line.yellow()),
            "blue" => println!("{}", line.blue()),
            "magenta" => println!("{}", line.magenta()),
            "cyan" => println!("{}", line.cyan()),
            "bright_red" => println!("{}", line.bright_red()),
            "bright_green" => println!("{}", line.bright_green()),
            "bright_yellow" => println!("{}", line.bright_yellow()),
            "bright_blue" => println!("{}", line.bright_blue()),
            "bright_magenta" => println!("{}", line.bright_magenta()),
            "bright_cyan" => println!("{}", line.bright_cyan()),
            _ => println!("{}", line),
        }
    }
    
    println!();
    println!("{}", "                            Author: OFJAAAH".bright_white().bold());
    println!("{}", "                    Subdomain Enumerator & Web Crawler".bright_white());
    println!();
}

fn main() -> anyhow::Result<()> {
    print_banner();
    let args = Args::parse();
    
    // Get domains from either single domain or file
    let domains = get_domains(&args)?;
    
    for domain in domains {
        println!("[*] Processing domain: {}", domain);
        process_domain(&domain)?;
        println!("[*] Completed processing domain: {}\n", domain);
    }
    
    Ok(())
}

fn get_domains(args: &Args) -> anyhow::Result<Vec<String>> {
    match (&args.domain, &args.file) {
        (Some(domain), None) => Ok(vec![domain.clone()]),
        (None, Some(file_path)) => {
            let file = File::open(file_path)?;
            let domains: Vec<String> = BufReader::new(file)
                .lines()
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
            
            if domains.is_empty() {
                return Err(anyhow::anyhow!("No domains found in file: {}", file_path));
            }
            
            Ok(domains)
        },
        (Some(_), Some(_)) => Err(anyhow::anyhow!("Cannot specify both domain and file arguments")),
        (None, None) => Err(anyhow::anyhow!("Must specify either --domain or --file argument")),
    }
}

fn process_domain(domain: &str) -> anyhow::Result<()> {
    // 1 & 2: create output directory
    fs::create_dir_all(domain)?;
    let base = Path::new(domain);

    // 3: enumerate subdomains via haktrails
    let subs_txt = base.join("subdomains.txt");
    println!("[*] Enumerating subdomains via haktrails...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {} | haktrails subdomains | anew {}",
            domain,
            subs_txt.display()
        ))
        .status()?;

    // 3.a: augment subdomains via TLS certificate SANs using tlsx
    println!("[*] Extracting certificate SANs with tlsx...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {} | tlsx -json -silent | jq -r '.subject_an[] | ltrimstr(\"*.\")' | anew {}",
            domain,
            subs_txt.display()
        ))
        .status()?;

    // 3.1: resolve subdomains to IPs via dnsx
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

    // 3.2: port scan with masscan on IPs (parallel with timeout)
    let masscan_txt = base.join("masscan.txt");
    let ports_txt = base.join("ports.txt");
    
    println!("[*] Starting parallel port scanning and validation...");
    let (tx, rx) = mpsc::channel();
    
    // Spawn masscan in background thread
    let masscan_txt_clone = masscan_txt.clone();
    let ips_txt_clone = ips_txt.clone();
    let tx_masscan = tx.clone();
    
    thread::spawn(move || {
        println!("[*] Scanning common ports with masscan (60s timeout)...");
        let result = Command::new("timeout")
            .arg("60s")
            .arg("sh")
            .arg("-c")
            .arg(format!(
                "masscan -iL {} --ports 80,443,8080,8443,8000,3000,5000,9000,22,21,25,53,110,143,993,995,587,465,23,2222,3389,5432,3306,1433,27017,6379,11211,9200,9300 --rate 50000 -oL {}",
                ips_txt_clone.display(),
                masscan_txt_clone.display()
            ))
            .status();
        
        match result {
            Ok(status) if status.success() => {
                println!("[+] Masscan completed successfully");
                let _ = tx_masscan.send(true);
            },
            Ok(_) => {
                println!("[!] Masscan timed out or completed with errors");
                let _ = tx_masscan.send(false);
            },
            Err(e) => {
                println!("[!] Masscan failed: {}", e);
                let _ = tx_masscan.send(false);
            }
        }
    });
    
    // Continue with other tasks while masscan runs
    println!("[*] Continuing with other enumeration while port scan runs in background...");
    
    // Wait for masscan to complete (with 65 second timeout)
    let masscan_success = thread::spawn(move || {
        match rx.recv_timeout(std::time::Duration::from_secs(65)) {
            Ok(success) => success,
            Err(_) => {
                println!("[!] Masscan timeout exceeded, continuing...");
                false
            }
        }
    }).join().unwrap_or(false);
    
    // 3.3: validate open ports with httpx if masscan succeeded
    if masscan_success && masscan_txt.exists() {
        println!("[*] Validating open ports with httpx (30s timeout)...");
        let httpx_result = Command::new("timeout")
            .arg("30s")
            .arg("sh")
            .arg("-c")
            .arg(format!(
                r#"cat {} | awk '/open/ {{print $4 ":" $3}}' | head -100 | httpx -silent -timeout 3 -retries 1 -threads 50 -o {}"#,
                masscan_txt.display(),
                ports_txt.display()
            ))
            .status();
        
        match httpx_result {
            Ok(status) if status.success() => println!("[+] Port validation completed successfully"),
            Ok(_) => println!("[!] Port validation timed out (continuing...)"),
            Err(e) => println!("[!] Port validation failed: {} (continuing...)", e),
        }
    } else {
        println!("[!] Skipping port validation due to masscan issues");
    }

    // 4: resolve alive hosts via httpx
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

    // Prepare output files
    let mut s3_file = File::create(base.join("s3.txt"))?;
    let mut urls_file = File::create(base.join("urls.txt"))?;
    let mut hidden_file = File::create(base.join("hiddenparams.txt"))?;

    // Regex patterns
    let re_s3 = Regex::new(r"[a-z0-9\-]+\.s3\.amazonaws\.com")?;
    let re_comment_urls = Regex::new(r#"https?://[^"\s]+"#)?;
    let re_comments = Regex::new(r#"<!--([\s\S]*?)-->"#)?;
    let re_hidden = Regex::new(r#"<input[^>]+name=('?"?)([^"'>\s]+)("?'?)"#)?;

    // HTTP client
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Trackers to avoid duplicates
    let mut seen_s3: HashSet<String> = HashSet::new();
    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut seen_hidden: HashSet<String> = HashSet::new();

    // 5-7: crawl each alive URL
    let file = File::open(&http200_txt)?;
    for line in BufReader::new(file).lines() {
        let url = line?;
        println!("[+] Crawling: {}", url);
        if let Ok(resp) = client.get(&url).send() {
            if let Ok(body) = resp.text() {
                let document = Html::parse_document(&body);
                
                // 5: extract S3 buckets
                for cap in re_s3.find_iter(&body) {
                    let bucket = cap.as_str().to_string();
                    if seen_s3.insert(bucket.clone()) {
                        writeln!(s3_file, "{}", bucket)?;
                    }
                }
                
                // 6: extract in-scope links (<a> and comments)
                let sel = Selector::parse("a[href]").unwrap();
                for elem in document.select(&sel) {
                    if let Some(href) = elem.value().attr("href") {
                        let full_url = if href.starts_with("http") {
                            href.to_string()
                        } else if href.starts_with('/') {
                            format!("{}{}", url.trim_end_matches('/'), href)
                        } else {
                            format!("{}/{}", url.trim_end_matches('/'), href)
                        };
                        
                        if full_url.contains(domain) && seen_urls.insert(full_url.clone()) {
                            // Check this URL for content size
                            if let Ok(link_resp) = client.get(&full_url).send() {
                                if let Ok(link_body) = link_resp.text() {
                                    let link_size = link_body.len();
                                    writeln!(urls_file, "{} [{}bytes]", full_url, link_size)?;
                                } else {
                                    writeln!(urls_file, "{} [0bytes]", full_url)?;
                                }
                            } else {
                                writeln!(urls_file, "{} [no-response]", full_url)?;
                            }
                        }
                    }
                }
                
                for caps in re_comments.captures_iter(&body) {
                    let comment_text = &caps[1];
                    for url_cap in re_comment_urls.find_iter(comment_text) {
                        let link = url_cap.as_str().trim_end_matches('"').to_string();
                        if link.contains(domain) && seen_urls.insert(link.clone()) {
                            // Check this URL for content size
                            if let Ok(link_resp) = client.get(&link).send() {
                                if let Ok(link_body) = link_resp.text() {
                                    let link_size = link_body.len();
                                    writeln!(urls_file, "{} [{}bytes]", link, link_size)?;
                                } else {
                                    writeln!(urls_file, "{} [0bytes]", link)?;
                                }
                            } else {
                                writeln!(urls_file, "{} [no-response]", link)?;
                            }
                        }
                    }
                }
                
                // 7: extract hidden parameters and build URLs
                if let Some(hurls) = extract_hidden_params(&url, &body, &re_hidden) {
                    for hurl in hurls {
                        if seen_hidden.insert(hurl.clone()) {
                            // Check this URL for content size
                            if let Ok(hidden_resp) = client.get(&hurl).send() {
                                if let Ok(hidden_body) = hidden_resp.text() {
                                    let hidden_size = hidden_body.len();
                                    writeln!(hidden_file, "{} [{}bytes]", hurl, hidden_size)?;
                                } else {
                                    writeln!(hidden_file, "{} [0bytes]", hurl)?;
                                }
                            } else {
                                writeln!(hidden_file, "{} [no-response]", hurl)?;
                            }
                        }
                    }
                }
            }
        }
    }

    // 8: extract all params via hakrawler
    println!("[*] Extracting params with hakrawler...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | hakrawler -s href -subs | anew {}",
            http200_txt.display(),
            base.join("params.txt").display()
        ))
        .status()?;

    // 8.5: directory bruteforcing with ffuf
    println!("[*] Running directory bruteforcing with ffuf (silently using wordlist)...");
    let ffuf_output = base.join("ffuf_results.json");
    let discovered_paths = base.join("discovered_paths.txt");
    let wordlist_path = "/root/PENTEST/enumrust/enumrust/src/words_and_files_top5000.txt";
    
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | while read url; do echo '[*] Brute forcing: '$url; ffuf -w {} -u \"$url/FUZZ\" -ac -s -t 50 -mc 200 -e .php,.html,.js,.txt,.json,.xml,.bak,.old -o {}_$(echo \"$url\" | sed 's|https\\?://||g' | tr '/' '_').json -of json >/dev/null 2>&1; done",
            http200_txt.display(),
            wordlist_path,
            ffuf_output.display()
        ))
        .status()?;

    // Process ffuf JSON results to extract URL+path with sizes, only status 200
    println!("[*] Processing ffuf results...");
    let mut discovered_file = File::create(&discovered_paths)?;
    let mut seen_discovered: HashSet<String> = HashSet::new();
    
    // Find all ffuf JSON result files
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries {
            if let Ok(entry) = entry {
                let filename = entry.file_name();
                if let Some(name_str) = filename.to_str() {
                    if name_str.starts_with("ffuf_results") && name_str.ends_with(".json") {
                        if let Ok(json_content) = fs::read_to_string(entry.path()) {
                            // Parse ffuf JSON results
                            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&json_content) {
                                if let Some(results) = json_value.get("results").and_then(|r| r.as_array()) {
                                    for result in results {
                                        if let (Some(url), Some(status), Some(length)) = (
                                            result.get("url").and_then(|u| u.as_str()),
                                            result.get("status").and_then(|s| s.as_u64()),
                                            result.get("length").and_then(|l| l.as_u64())
                                        ) {
                                            // Only show status code 200 results
                                            if status == 200 && seen_discovered.insert(url.to_string()) {
                                                // Print full URL with size
                                                println!("{} [{}bytes]", url, length);
                                                writeln!(discovered_file, "{} [{}bytes]", url, length)?;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 9: fast vulnerability scanning with Nuclei
    println!("[*] Running Nuclei scan (fast mode)...");
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | nuclei -silent -etags ssl -l {} -c 100 -o {}",
            http200_txt.display(),
            http200_txt.display(),
            base.join("nuclei.txt").display()
        ))
        .status()?;

    println!(
        "[*] Done. Results saved in \"{}\" directory. Files: subdomains.txt, masscan.txt, ports.txt, http200.txt, s3.txt, urls.txt, hiddenparams.txt, params.txt, discovered_paths.txt, ffuf_results*.json, nuclei.txt",
        domain
    );
    Ok(())
}

/// Extracts hidden <input name="..."> fields and constructs URLs with airi payload
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
