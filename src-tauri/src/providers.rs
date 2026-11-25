use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

const BUNDLED: &str = include_str!("../resources/providers.json");
const REPO: &str = "VPSDance/ai-proxy-rules";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct RuleSet {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub process_name: Vec<String>,
    pub ip_cidr: Vec<String>,
    pub ip_cidr6: Vec<String>,
    pub asn: Vec<serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Group {
    pub name: String,
    pub rules: RuleSet,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Provider {
    pub provider: String,
    pub name: String,
    pub description: String,
    pub scope: String,
    pub categories: Vec<String>,
    pub aliases: Vec<String>,
    pub groups: Vec<Group>,
}

impl Provider {
    pub fn rule_count(&self) -> usize {
        self.groups
            .iter()
            .map(|g| {
                let r = &g.rules;
                r.domain.len()
                    + r.domain_suffix.len()
                    + r.domain_keyword.len()
                    + r.process_name.len()
                    + r.ip_cidr.len()
                    + r.ip_cidr6.len()
                    + r.asn.len()
            })
            .sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProviderDb {
    pub source: String,
    pub updated_at: u64,
    pub providers: Vec<Provider>,
}

impl ProviderDb {
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.provider == id)
    }
}

pub fn load(cache: &Path) -> ProviderDb {
    let cached = std::fs::read_to_string(cache).ok().and_then(|t| serde_json::from_str::<ProviderDb>(&t).ok());
    let bundled: ProviderDb = serde_json::from_str(BUNDLED).unwrap_or_default();
    match cached {
        Some(c) if !c.providers.is_empty() && c.updated_at >= bundled.updated_at => c,
        _ => bundled,
    }
}

#[derive(Deserialize)]
struct FlatListing {
    files: Vec<FlatFile>,
}

#[derive(Deserialize)]
struct FlatFile {
    name: String,
}

#[derive(Deserialize)]
struct GitTree {
    tree: Vec<GitEntry>,
}

#[derive(Deserialize)]
struct GitEntry {
    path: String,
}

/// Lists repo files. jsDelivr's listing can lag far behind, so GitHub's tree API comes first.
async fn list_files(client: &reqwest::Client) -> Result<Vec<String>, String> {
    let gh = async {
        let t: GitTree = client
            .get(format!("https://api.github.com/repos/{REPO}/git/trees/main?recursive=1"))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json()
            .await
            .ok()?;
        Some(t.tree.into_iter().map(|e| format!("/{}", e.path)).collect::<Vec<_>>())
    };
    if let Some(files) = gh.await {
        return Ok(files);
    }
    let listing: FlatListing = client
        .get(format!("https://data.jsdelivr.com/v1/packages/gh/{REPO}@main?structure=flat"))
        .send()
        .await
        .map_err(|e| format!("获取文件列表失败: {e}"))?
        .json()
        .await
        .map_err(|e| format!("解析文件列表失败: {e}"))?;
    Ok(listing.files.into_iter().map(|f| f.name).collect())
}

async fn download(client: &reqwest::Client, path: &str) -> Option<String> {
    for url in [
        format!("https://cdn.jsdelivr.net/gh/{REPO}@main{path}"),
        format!("https://raw.githubusercontent.com/{REPO}/main{path}"),
    ] {
        if let Ok(r) = client.get(&url).send().await {
            if r.status().is_success() {
                if let Ok(t) = r.text().await {
                    return Some(t);
                }
            }
        }
    }
    None
}

/// Downloads every `data/providers/*.yaml` from the VPSDance repo.
pub async fn fetch_latest() -> Result<ProviderDb, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("NetDect/0.1")
        .build()
        .map_err(|e| e.to_string())?;
    let files: Vec<String> = list_files(&client)
        .await?
        .into_iter()
        .filter(|n| n.starts_with("/data/providers/") && n.ends_with(".yaml") && n.matches('/').count() == 3)
        .collect();
    if files.is_empty() {
        return Err("文件列表中没有 provider".into());
    }

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let mut set = tokio::task::JoinSet::new();
    for f in files {
        let client = client.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let text = download(&client, &f).await?;
            let mut p = serde_yaml::from_str::<Provider>(&text).ok().filter(|p| !p.provider.is_empty())?;
            if p.scope.is_empty() {
                p.scope = "global".into();
            }
            Some(p)
        });
    }
    let mut providers = Vec::new();
    let mut failed = 0;
    while let Some(r) = set.join_next().await {
        match r.ok().flatten() {
            Some(p) => providers.push(p),
            None => failed += 1,
        }
    }
    if providers.is_empty() || failed > providers.len() / 5 {
        return Err(format!("下载不完整：成功 {}，失败 {failed}", providers.len()));
    }
    providers.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(ProviderDb {
        source: format!("https://github.com/{REPO}"),
        updated_at: crate::config::now_secs(),
        providers,
    })
}
