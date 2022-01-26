use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    fmt::Debug,
};

use anyhow::{anyhow, Result};
use clap::{App, Arg};
use futures_util::{future, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;
use reqwest::{Client, Proxy, Response};
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt, process::Command};
use walkdir::WalkDir;
#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("mediawiki extension helper")
        .version("0.1.0")
        .arg(Arg::new("proxy").long("proxy").takes_value(true))
        .subcommand(App::new("init").arg(Arg::new("version").index(1).help("x.x.x").required(true)))
        .subcommand(
            App::new("add")
                // .arg(
                //     Arg::new("type")
                //         .help("ext or skin")
                //         .takes_value(true)
                //         .required(true),
                // )
                .arg(
                    Arg::new("ext")
                        .short('e')
                        .multiple_values(true)
                        .takes_value(true),
                ),
        )
        .subcommand(App::new("update"))
        .get_matches();
    let mut client = Client::builder();
    if let Some(proxy) = matches.value_of("proxy") {
        client = client.proxy(Proxy::all(proxy)?);
    }
    let client = client.build()?;

    if let Some(args) = matches.subcommand_matches("init") {
        let version = parse_version(args.value_of("version").unwrap())?;
        ensure_dir().await?;
        install_mw(&version, &client).await?;
        create_json(&version).await?;
        return Ok(());
    }
    if let Some(args) = matches.subcommand_matches("add") {
        let mut config = read_json().await?;
        ensure_dir().await?;
        let exts = args.values_of("ext").unwrap().unique().collect_vec();
        let multi = MultiProgress::new();

        let result = future::join_all(
            exts.clone()
                .into_iter()
                .map(|ext| install_ext(&config.version, ext.to_string(), &multi, &client)),
        );
        let result = result.await;
        // multi.clear()?;
        result
            .iter()
            .enumerate()
            .for_each(|(index, result)| match result {
                Ok(hash) => {
                    config.ext.insert(exts[index].to_string(), hash.to_string());
                }
                Err(err) => {
                    println!("{} install failed: {}", exts[index], err)
                }
            });
        config.save().await?;
        return Ok(());
    }
    if let Some(args) = matches.subcommand_matches("update") {}
    Ok(())
}
async fn ensure_dir() -> Result<()> {
    fs::create_dir_all(".wem").await?;
    Ok(())
}
async fn save_with_progress(
    resp: Response,
    filename: &str,
    filepath: &str,
    total_size: u64,
    pb: &ProgressBar,
) -> Result<()> {
    let mut file = fs::File::create(filepath.clone()).await?;
    let mut downloaded: u64 = 0;
    let mut stream = resp.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.or(Err(anyhow!("Error while downloading file")))?;
        file.write(&chunk)
            .await
            .or(Err(anyhow!("Error while writing to file")))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }
    // unset_pb_style(pb);
    Ok(())
}
fn remove_git_ignore(base: &str) -> Result<()> {
    for entry in WalkDir::new(base).into_iter() {
        if let Ok(entry) = entry {
            if entry.file_type().is_file() && entry.file_name() == ".gitignore" {
                println!(
                    ".gitignore find at {}, removing",
                    entry.path().canonicalize()?.to_str().unwrap()
                );
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct Version(String, String, String);
impl Version {
    fn x_x(&self) -> String {
        format!("{}.{}", self.0, self.1)
    }
    fn x_x_x(&self) -> String {
        format!("{}.{}.{}", self.0, self.1, self.2)
    }
    fn rel(&self) -> String {
        format!("REL{}_{}", self.0, self.1)
    }
}
/// version: x.x.x
fn set_pb_style(pb: &ProgressBar) {
    pb
        .set_style(ProgressStyle::default_bar()
        .template("{prefix}: {msg} {spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .progress_chars("#>-"));
}
fn unset_pb_style(pb: &ProgressBar) {
    pb.set_style(ProgressStyle::default_bar().template("{prefix}: {msg} {spinner:.green}"));
}
fn get_total_size(resp: &Response, url: &str) -> Result<u64> {
    let total_size = resp.content_length().ok_or(anyhow!(format!(
        "Failed to get content length from '{}'",
        url
    )))?;
    Ok(total_size)
}
async fn unzip(path: &str, target_path: &str) -> Result<std::process::ExitStatus> {
    let mut child = Command::new("tar")
        .arg("-xzf")
        .arg(path)
        .arg("-C")
        .arg(target_path)
        .arg("--strip-components")
        .arg("1")
        .spawn()?;
    let status = child.wait().await?;
    Ok(status)
}
async fn install_mw(version: &Version, client: &Client) -> Result<()> {
    //https://releases.wikimedia.org/mediawiki/1.36/mediawiki-1.36.1.zip
    let url = format!(
        "https://releases.wikimedia.org/mediawiki/{}/mediawiki-{}.tar.gz",
        version.x_x(),
        version.x_x_x()
    );
    let filename = format!("mediawiki-{}.tar.gz", version.x_x_x());

    let resp = client.get(url.clone()).send().await?;
    let total_size = get_total_size(&resp, &url)?;
    let pb = ProgressBar::new(total_size);
    set_pb_style(&pb);
    pb.set_prefix(format!("mediawiki-{}", version.x_x_x()));
    let filepath = format!("./.wem/{}", filename);
    save_with_progress(resp, &filename, &filepath, total_size, &pb).await?;
    let status = unzip(&filepath, ".").await?;
    remove_git_ignore(".")?;
    pb.finish_with_message(format!(
        "mediawiki {} installed {}",
        version.x_x_x(),
        status
    ));
    Ok(())
}
fn parse_version(version: &str) -> Result<Version> {
    let version: Vec<&str> = version.split('.').collect();
    let major = version.get(0).ok_or(anyhow!("wrong version format"))?;
    let minor = version.get(1).ok_or(anyhow!("wrong version format"))?;
    let patch = version.get(2).ok_or(anyhow!("wrong version format"))?;
    Ok(Version(
        major.to_string(),
        minor.to_string(),
        patch.to_string(),
    ))
}
#[derive(Deserialize, Serialize, Debug, Default)]
struct Config {
    version: Version,
    ext: HashMap<String, String>,
    skin: HashMap<String, String>,
}
impl Config {
    async fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write("wem.json", json).await?;
        Ok(())
    }
}
async fn create_json(version: &Version) -> Result<()> {
    let json = serde_json::to_string_pretty(&Config {
        version: version.to_owned(),
        ..Default::default()
    })?;
    fs::write("wem.json", json).await?;
    Ok(())
}

async fn read_json() -> Result<Config> {
    let s = fs::read_to_string("wem.json").await?;
    let json = serde_json::from_str::<Config>(&s)?;
    Ok(json)
}
#[derive(Deserialize, Debug)]
struct Resp {
    query: Query,
}
#[derive(Deserialize, Debug)]
struct Query {
    extdistbranches: Extdistbranches,
}
#[derive(Deserialize, Debug)]
struct Extdistbranches {
    extensions: HashMap<String, HashMap<String, String>>,
}
async fn fetch_ext_meta(
    version: &Version,
    name: &str,
    client: &Client,
) -> Result<(String, String)> {
    let meta = client
        .get("https://www.mediawiki.org/w/api.php")
        .query(&[
            ("action", "query"),
            ("list", "extdistbranches"),
            ("edbexts", name),
            ("format", "json"),
        ])
        .send()
        .await?
        .json::<Resp>()
        .await?;
    let branch = version.rel();
    let url = meta
        .query
        .extdistbranches
        .extensions
        .get(name)
        .ok_or(anyhow!("ext {} not found", name))?
        .get(&branch)
        .ok_or(anyhow!("ext {} version {} not found", name, branch))?;
    let start = url.rfind("/").ok_or(anyhow!("wrong url {}", url))?;
    let filename = &url[start..];
    Ok((url.to_string(), filename.to_string()))
}
async fn install_ext(
    version: &Version,
    name: String,
    mutli: &MultiProgress,
    client: &Client,
) -> Result<String> {
    let pb = mutli.add(ProgressBar::new(0));
    pb.set_prefix(name.clone());
    pb.set_style(ProgressStyle::default_bar().template("{prefix}: {msg} {spinner:.green}"));
    pb.set_message("fetching meta...");
    let (url, filename) = fetch_ext_meta(version, &name, client).await?;
    pb.set_message("downloading...");
    set_pb_style(&pb);
    let resp = client.get(&url).send().await?;
    let total_size = get_total_size(&resp, &url)?;
    pb.set_length(total_size);
    let filepath = format!(".wem/{}", filename);
    save_with_progress(resp, &filename, &filepath, total_size, &pb).await?;
    let target_path = format!("extensions/{}/", name);
    fs::create_dir_all(&target_path).await?;
    let status = unzip(&filepath, &target_path).await?;
    remove_git_ignore(&target_path)?;
    // pb.set_message("waiting...");
    // pb.finish_and_clear();
    pb.finish_with_message("waiting...");
    let hash_start = filename.find('-').ok_or(anyhow!("wrong filename"))? + 1;
    let hash_end = filename.find('.').ok_or(anyhow!("wrong filename"))?;
    let hash = &filename[hash_start..hash_end];
    Ok(hash.to_string())
}
