use crate::checker::Report;

fn status_text(s: &str) -> &'static str {
    match s {
        "pass" => "✅ 通过",
        "fail" => "❌ 失败",
        "warn" => "⚠️ 未验证",
        "skip" => "➖ 跳过",
        "info" => "ℹ️ 信息",
        _ => "?",
    }
}

fn method_text(s: &str) -> &'static str {
    match s {
        "measured" => "实测",
        "attributed" => "归因",
        "sampled" => "抽样",
        _ => "-",
    }
}

fn esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn to_markdown(r: &Report) -> String {
    let mut s = String::new();
    s.push_str("# NetDect 检测报告\n\n");
    s.push_str(&format!("- 结果：{} {}\n", status_text(&r.status), r.summary));
    s.push_str(&format!("- 目标出口：{}（期望 IP {}，来源：{}）\n", r.target_name, r.expected_ip,
        if r.expected_source == "pinned" { "手动固定" } else { "经该出口实测" }));
    s.push_str(&format!("- 探测方式：{}\n", r.route));
    s.push_str(&format!(
        "- 代理软件 API：{}\n",
        r.engine.clone().unwrap_or_else(|| format!("不可用（{}）", r.engine_error.clone().unwrap_or_default()))
    ));
    s.push_str(&format!(
        "- IP 回显服务：{}（NetDect 自身出口 {}）\n",
        r.echo_url.clone().unwrap_or_else(|| "不可用".into()),
        r.baseline_ip.clone().unwrap_or_else(|| "-".into())
    ));
    s.push_str(&format!("- 时间：{} → {}（Unix 秒）\n\n", r.started_at, r.finished_at));

    s.push_str("## 环境检查\n\n| 项目 | 状态 | 说明 |\n| :--- | :--- | :--- |\n");
    for c in &r.env {
        s.push_str(&format!("| {} | {} | {} |\n", esc(&c.name), status_text(&c.status), esc(&c.detail)));
    }
    for a in &r.apps {
        s.push_str(&format!(
            "\n## {}（{}）\n\n{}：通过 {} · 失败 {} · 未验证 {} · 跳过 {}\n",
            a.name, a.id, status_text(&a.status), a.pass, a.fail, a.warn, a.skip
        ));
        if !a.discovered_roots.is_empty() {
            s.push_str(&format!("\n本机安装位置：{}\n", a.discovered_roots.join("；")));
        }
        s.push_str("\n| 状态 | 类型 | 目标 | 方法 | 出口 IP | 命中规则 / 链路 | 说明 |\n| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for i in &a.items {
            let chain = if i.chain.is_empty() {
                i.rule.clone().unwrap_or_default()
            } else {
                format!("{} → {}", i.rule.clone().unwrap_or_default(), i.chain.iter().rev().cloned().collect::<Vec<_>>().join(" → "))
            };
            let ip = match (&i.observed_ip, &i.observed_loc) {
                (Some(ip), Some(loc)) => format!("{ip}（{loc}）"),
                (Some(ip), None) => ip.clone(),
                _ => String::new(),
            };
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                status_text(&i.status),
                esc(&i.kind),
                esc(&i.target),
                method_text(&i.method),
                esc(&ip),
                esc(&chain),
                esc(&i.note)
            ));
        }
    }
    s
}
