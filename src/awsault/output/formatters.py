"""
Output formatters for JSON, CSV, and HTML.

All functions accept plain dicts (as stored by store.py or produced by
converting live scan results via ServiceResult.to_dict()). This keeps
the formatters decoupled from the scanner's internal objects.
"""

import csv
import io
import json
import datetime


def _serial(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return "<binary>"
    return str(obj)


def _esc(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def save_json(filepath, data):
    """Write the full scan data dict to a JSON file."""
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=_serial)


def save_csv(filepath, data):
    """Write a flat CSV with one row per API call, plus findings and loot sections."""
    with open(filepath, "w", newline="") as f:
        w = csv.writer(f)

        services = data.get("services", {})
        if services:
            w.writerow(["service", "method", "status", "item_count", "error"])
            for name, svc in sorted(services.items()):
                for c in svc.get("calls", []):
                    w.writerow([name, c["method"], c["status"],
                                c.get("count", 0), c.get("error", "")])
            w.writerow([])

        findings = data.get("findings", [])
        if findings:
            w.writerow(["severity", "service", "resource", "title", "detail", "recommendation"])
            for f in findings:
                w.writerow([f["severity"], f["service"], f["resource"],
                            f["title"], f.get("detail", ""), f.get("recommendation", "")])
            w.writerow([])

        loot = data.get("loot", {})
        if loot:
            w.writerow(["source", "name", "readable"])
            for source, items in loot.items():
                for item in items:
                    name = item.get("Name") or item.get("FunctionName") or item.get("InstanceId") or item.get("StackName") or item.get("ProjectName") or "?"
                    w.writerow([source, name, item.get("Readable", "")])
            w.writerow([])

        recon = data.get("recon", {})
        if recon:
            w.writerow(["## identity_recon"])
            w.writerow(["identity", f"{recon.get('Type', '?')}/{recon.get('Principal', '?')}"])
            w.writerow(["account", recon.get("Account", "")])
            w.writerow(["arn", recon.get("Arn", "")])
            w.writerow(["groups", ", ".join(recon.get("Groups", [])) or "(none)"])
            w.writerow([])

            policies = recon.get("Policies", [])
            if policies:
                w.writerow(["policy_name", "policy_type", "attached_to", "effect", "actions", "resources"])
                for pol in policies:
                    for stmt in pol.get("Statements", []):
                        w.writerow([
                            pol["Name"], pol["Type"], pol.get("AttachedTo", ""),
                            stmt["Effect"],
                            "; ".join(stmt.get("Actions", [])),
                            "; ".join(stmt.get("Resources", [])),
                        ])
                w.writerow([])

            roles = recon.get("AssumableRoles", [])
            if roles:
                w.writerow(["## assumable_roles"])
                w.writerow(["role_name", "role_arn", "reason", "policy_name", "policy_type", "effect", "actions", "resources"])
                for role in roles:
                    for pol in role.get("Policies", []):
                        for stmt in pol.get("Statements", []):
                            w.writerow([
                                role["RoleName"], role.get("Arn", ""), role.get("Reason", ""),
                                pol["Name"], pol.get("Type", ""),
                                stmt["Effect"],
                                "; ".join(stmt.get("Actions", [])),
                                "; ".join(stmt.get("Resources", [])),
                            ])
                w.writerow([])

            privesc = recon.get("PrivescPaths", [])
            if privesc:
                w.writerow(["## privilege_escalation_paths"])
                w.writerow(["severity", "name", "action", "via_policy", "via_role", "resources", "description"])
                for p in privesc:
                    w.writerow([
                        p.get("Severity", ""), p.get("Name", ""), p["Action"],
                        p.get("ViaPolicy", ""), p.get("ViaRole", ""),
                        "; ".join(p.get("Resources", [])), p.get("Description", ""),
                    ])
                    for av in p.get("AlternateVersions", []):
                        w.writerow([
                            "  alt_version", av.get("PolicyName", ""), av.get("VersionId", ""),
                            av.get("PolicyArn", ""), "",
                            "; ".join("; ".join(s.get("Actions", [])) for s in av.get("Statements", [])),
                            "",
                        ])


def save_html(filepath, data):
    """Generate a self-contained HTML report with tabs for services, findings, and loot."""
    meta = data.get("meta", {})
    services = data.get("services", {})
    findings = data.get("findings", [])
    loot = data.get("loot", {})

    account = meta.get("account", "?")
    arn = meta.get("arn", "?")
    region = meta.get("region", "?")
    mode = meta.get("mode", "?")

    svc_count = len(services)
    total_calls = sum(s.get("summary", {}).get("total", 0) for s in services.values())
    total_ok = sum(s.get("summary", {}).get("ok", 0) for s in services.values())
    total_denied = sum(s.get("summary", {}).get("denied", 0) for s in services.values())
    total_err = sum(s.get("summary", {}).get("errors", 0) for s in services.values())
    finding_count = len(findings)
    loot_count = sum(len(v) for v in loot.values())
    crit_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
    high_count = len([f for f in findings if f.get("severity") == "HIGH"])

    sev_colors = {"CRITICAL": "#f85149", "HIGH": "#db6d28", "MEDIUM": "#d29922", "LOW": "#58a6ff", "INFO": "#8b949e"}

    # build service cards
    svc_cards = ""
    for name in sorted(services.keys()):
        s = services[name]
        sm = s.get("summary", {})
        ok, total = sm.get("ok", 0), sm.get("total", 0)
        badge = "badge-ok" if ok == total else ("badge-partial" if ok > 0 else "badge-denied")

        rows = ""
        for c in s.get("calls", []):
            if c["status"] == "ok":
                st = f'<span class="st-ok">OK ({c.get("count", 0)})</span>'
                err = ""
            elif c["status"] == "denied":
                st = '<span class="st-denied">DENIED</span>'
                err = f"<small>{_esc(c.get('error', ''))}</small>"
            else:
                st = '<span class="st-err">ERROR</span>'
                err = f"<small>{_esc(c.get('error', ''))}</small>"
            rows += f"<tr><td><code>{c['method']}</code></td><td>{st}</td><td>{err}</td></tr>\n"

        svc_cards += f'''<div class="card svc-card" data-status="{badge}" data-name="{name}">
<div class="card-hd" onclick="toggle(this)"><span class="svc-n">{name.upper()}</span><span class="badge {badge}">{ok}/{total}</span></div>
<div class="card-bd" style="display:none"><table><thead><tr><th>API Call</th><th>Status</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div></div>\n'''

    # build findings
    findings_html = ""
    for f in findings:
        color = sev_colors.get(f.get("severity", ""), "#8b949e")
        findings_html += f'''<div class="finding"><span class="sev" style="background:{color}22;color:{color}">{f["severity"]}</span>
<span class="f-svc">{f["service"]}</span><span class="f-res">{_esc(f["resource"])}</span>
<div class="f-title">{_esc(f["title"])}</div><div class="f-detail">{_esc(f.get("detail", ""))}</div>
<div class="f-rec">{_esc(f.get("recommendation", ""))}</div></div>\n'''

    # build loot
    loot_html = ""
    for source, items in loot.items():
        if not items:
            continue
        loot_html += f'<h3 class="loot-src">{_esc(source)} ({len(items)})</h3>'
        for item in items:
            dumped = _esc(json.dumps(item, indent=2, default=_serial))
            iname = item.get("Name") or item.get("FunctionName") or item.get("InstanceId") or item.get("StackName") or item.get("ProjectName") or "?"
            r = item.get("Readable")
            rb = '<span class="st-ok">READABLE</span>' if r is True else ('<span class="st-denied">DENIED</span>' if r is False else "")
            loot_html += f'<div class="loot-item"><div class="loot-hd" onclick="toggle(this)"><code>{_esc(str(iname))}</code> {rb}</div><pre class="loot-bd" style="display:none">{dumped}</pre></div>\n'

    # build recon
    recon = data.get("recon", {})
    recon_html = ""
    recon_roles_count = len(recon.get("AssumableRoles", []))
    recon_policies_count = len(recon.get("Policies", []))
    recon_privesc_count = len(recon.get("PrivescPaths", []))
    if recon:
        rid = _esc(f"{recon.get('Type', '?')}/{recon.get('Principal', '?')}")
        racc = _esc(recon.get("Account", "?"))
        rarn = _esc(recon.get("Arn", "?"))
        rgroups = _esc(", ".join(recon.get("Groups", [])) or "(none)")

        recon_html += f'''<div class="recon-id"><div class="recon-row"><span class="recon-l">Identity</span><span class="recon-v">{rid}</span></div>
<div class="recon-row"><span class="recon-l">Account</span><span class="recon-v">{racc}</span></div>
<div class="recon-row"><span class="recon-l">ARN</span><span class="recon-v" style="font-size:.85rem">{rarn}</span></div>
<div class="recon-row"><span class="recon-l">Groups</span><span class="recon-v">{rgroups}</span></div></div>'''

        # policies
        policies = recon.get("Policies", [])
        if policies:
            recon_html += f'<h3 style="color:var(--grn);margin:1.2rem 0 .6rem">Effective Policies ({len(policies)})</h3>'
            for pol in policies:
                pname = _esc(pol["Name"])
                ptype = pol["Type"]
                attached_to = _esc(pol.get("AttachedTo", ""))
                type_badge = {"inline": "badge-partial", "aws-managed": "badge-ok"}.get(ptype, "badge-ok")
                type_label = {"inline": "inline", "aws-managed": "AWS managed"}.get(ptype, "customer managed")
                pol_arn = f'<div style="color:var(--dim);font-size:.8rem;margin:.2rem 0 .4rem 1rem">{_esc(pol["Arn"])}</div>' if pol.get("Arn") else ""

                stmts_html = ""
                for stmt in pol.get("Statements", []):
                    effect = stmt["Effect"]
                    actions = stmt.get("Actions", [])
                    resources = stmt.get("Resources", [])
                    cond = ' <span style="color:var(--dim)">(conditional)</span>' if stmt.get("Condition") else ""
                    if effect == "Allow":
                        ec, es = "var(--grn)", "Allow"
                    else:
                        ec, es = "var(--red)", "Deny"
                    act_str = _esc(", ".join(actions[:8]))
                    if len(actions) > 8:
                        act_str += f' <span style="color:var(--dim)">(+{len(actions) - 8} more)</span>'
                    res_html = "".join(f'<div style="color:var(--dim);margin-left:1rem;font-size:.82rem">&rarr; {_esc(r)}</div>' for r in resources[:5])
                    if len(resources) > 5:
                        res_html += f'<div style="color:var(--dim);margin-left:1rem;font-size:.82rem">&rarr; (+{len(resources) - 5} more)</div>'
                    stmts_html += f'<div class="recon-stmt"><span style="color:{ec};font-weight:600">{es}:{cond}</span> {act_str}{res_html}</div>'

                recon_html += f'''<div class="card" style="margin-bottom:.4rem"><div class="card-hd" onclick="toggle(this)">
<span><strong>{pname}</strong> <span class="badge {type_badge}">{type_label}</span> <span style="color:var(--dim)">on {attached_to}</span></span></div>
<div class="card-bd" style="display:none">{pol_arn}{stmts_html}</div></div>\n'''

        # assumable roles
        roles = recon.get("AssumableRoles", [])
        if roles:
            recon_html += f'<h3 style="color:var(--red);margin:1.2rem 0 .6rem">Assumable Roles ({len(roles)})</h3>'
            for role in roles:
                rname = _esc(role.get("RoleName", "?"))
                rdesc = _esc(role.get("Description", ""))
                rreason = _esc(role.get("Reason", ""))
                role_arn = _esc(role.get("Arn", ""))

                role_body = f'<div style="color:var(--dim);font-size:.85rem;margin-bottom:.5rem">Why: {rreason}<br>{role_arn}</div>'

                for rpol in role.get("Policies", []):
                    rpname = _esc(rpol["Name"])
                    rptype = rpol.get("Type", "")
                    role_body += f'<div style="font-weight:600;margin:.4rem 0 .2rem">{rpname} <span style="color:var(--dim);font-weight:400">({rptype})</span></div>'
                    for stmt in rpol.get("Statements", []):
                        effect = stmt["Effect"]
                        actions = stmt.get("Actions", [])
                        resources = stmt.get("Resources", [])
                        if effect == "Allow":
                            ec, es = "var(--grn)", "Allow"
                        else:
                            ec, es = "var(--red)", "Deny"
                        act_str = _esc(", ".join(actions[:8]))
                        if len(actions) > 8:
                            act_str += f' <span style="color:var(--dim)">(+{len(actions) - 8})</span>'
                        res_html = "".join(f'<div style="color:var(--dim);margin-left:1rem;font-size:.82rem">&rarr; {_esc(r)}</div>' for r in resources[:5])
                        if len(resources) > 5:
                            res_html += f'<div style="color:var(--dim);margin-left:1rem;font-size:.82rem">&rarr; (+{len(resources) - 5} more)</div>'
                        role_body += f'<div class="recon-stmt"><span style="color:{ec};font-weight:600">{es}:</span> {act_str}{res_html}</div>'

                recon_html += f'''<div class="card" style="margin-bottom:.4rem;border-color:rgba(248,81,73,.3)"><div class="card-hd" onclick="toggle(this)">
<span><strong>{rname}</strong>{f' <span style="color:var(--dim)">&mdash; {rdesc}</span>' if rdesc else ''}</span></div>
<div class="card-bd" style="display:none">{role_body}</div></div>\n'''

        # privilege escalation paths
        privesc = recon.get("PrivescPaths", [])
        if privesc:
            recon_html += f'<h3 style="color:var(--red);margin:1.2rem 0 .6rem">&#9888; Privilege Escalation Paths ({len(privesc)})</h3>'
            for p in privesc:
                sev = p.get("Severity", "MEDIUM")
                sev_color = sev_colors.get(sev, "#d29922")
                via = f' <span style="color:var(--dim)">(via role {_esc(p.get("ViaRole", ""))})</span>' if p.get("ViaRole") else ""
                pe_body = f'<div style="color:var(--dim);font-size:.85rem;margin-bottom:.4rem">{_esc(p.get("Description", ""))}</div>'
                pe_body += f'<div style="font-size:.85rem">Action: <code style="color:var(--acc)">{_esc(p["Action"])}</code> <span style="color:var(--dim)">in policy &quot;{_esc(p.get("ViaPolicy", ""))}&quot;</span></div>'

                resources = p.get("Resources", [])
                if resources:
                    for res in resources[:5]:
                        pe_body += f'<div style="color:var(--dim);margin-left:1rem;font-size:.82rem">&rarr; {_esc(res)}</div>'

                alt_versions = p.get("AlternateVersions", [])
                if alt_versions:
                    pe_body += '<div style="margin-top:.5rem;font-weight:600;color:var(--yel)">Available policy versions to switch to:</div>'
                    for av in alt_versions:
                        pe_body += f'<div style="margin:.3rem 0 .2rem .5rem"><span style="color:var(--yel)">&#9632;</span> <strong>{_esc(av.get("PolicyName", ""))}</strong> version <strong>{_esc(av.get("VersionId", ""))}</strong></div>'
                        for stmt in av.get("Statements", []):
                            effect = stmt["Effect"]
                            actions = stmt.get("Actions", [])
                            res_list = stmt.get("Resources", [])
                            ec = "var(--grn)" if effect == "Allow" else "var(--red)"
                            act_str = _esc(", ".join(actions[:8]))
                            if len(actions) > 8:
                                act_str += f' <span style="color:var(--dim)">(+{len(actions) - 8})</span>'
                            res_html_av = "".join(f'<div style="color:var(--dim);margin-left:2rem;font-size:.82rem">&rarr; {_esc(r)}</div>' for r in res_list[:5])
                            pe_body += f'<div class="recon-stmt" style="margin-left:1.5rem"><span style="color:{ec};font-weight:600">{effect}:</span> {act_str}{res_html_av}</div>'

                recon_html += f'''<div class="card" style="margin-bottom:.4rem;border-color:rgba(248,81,73,.5)"><div class="card-hd" onclick="toggle(this)">
<span><span class="sev" style="background:{sev_color}22;color:{sev_color}">{sev}</span> <strong>{_esc(p.get("Name", ""))}</strong>{via}</span></div>
<div class="card-bd" style="display:none">{pe_body}</div></div>\n'''

    # tabs
    tabs = '<div class="tabs"><div class="tab active" onclick="showTab(\'services\',this)">Services</div>'
    if findings:
        tabs += f'<div class="tab" onclick="showTab(\'findings\',this)">Findings ({finding_count})</div>'
    if loot:
        tabs += f'<div class="tab" onclick="showTab(\'loot\',this)">Loot ({loot_count})</div>'
    if recon:
        privesc_label = f' / {recon_privesc_count}E' if recon_privesc_count else ''
        tabs += f'<div class="tab" onclick="showTab(\'recon\',this)">Recon ({recon_policies_count}P / {recon_roles_count}R{privesc_label})</div>'
    tabs += '</div>'

    html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AWSault Report</title>
<style>:root{{--bg:#0d1117;--card:#161b22;--brd:#30363d;--tx:#c9d1d9;--dim:#8b949e;--acc:#58a6ff;--grn:#3fb950;--red:#f85149;--yel:#d29922;--org:#db6d28}}*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);padding:2rem;line-height:1.5}}h1{{color:var(--acc);font-size:2rem;letter-spacing:2px;text-align:center}}.sub{{text-align:center;color:var(--dim);margin-bottom:1.5rem}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.8rem;margin-bottom:2rem}}.stat{{background:var(--card);border:1px solid var(--brd);border-radius:8px;padding:.8rem 1rem}}.stat .l{{color:var(--dim);font-size:.75rem;text-transform:uppercase;letter-spacing:1px}}.stat .v{{font-size:1.4rem;font-weight:700;margin-top:.2rem}}.v-g{{color:var(--grn)}}.v-r{{color:var(--red)}}.v-y{{color:var(--yel)}}.v-a{{color:var(--acc)}}.tabs{{display:flex;gap:0;margin-bottom:1.5rem;border-bottom:1px solid var(--brd)}}.tab{{padding:.6rem 1.2rem;cursor:pointer;color:var(--dim);border-bottom:2px solid transparent;font-size:.9rem}}.tab:hover{{color:var(--tx)}}.tab.active{{color:var(--acc);border-color:var(--acc)}}.panel{{display:none}}.panel.active{{display:block}}.card{{background:var(--card);border:1px solid var(--brd);border-radius:8px;margin-bottom:.5rem;overflow:hidden}}.card-hd{{display:flex;justify-content:space-between;align-items:center;padding:.7rem 1rem;cursor:pointer}}.card-hd:hover{{background:rgba(88,166,255,.04)}}.svc-n{{font-weight:600;font-size:.9rem;letter-spacing:1px}}.badge{{padding:.1rem .5rem;border-radius:12px;font-size:.75rem;font-weight:600}}.badge-ok{{background:rgba(63,185,80,.12);color:var(--grn)}}.badge-partial{{background:rgba(210,153,34,.12);color:var(--yel)}}.badge-denied{{background:rgba(248,81,73,.12);color:var(--red)}}.card-bd{{padding:0 1rem .8rem}}table{{width:100%;border-collapse:collapse;font-size:.85rem}}th{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--brd);color:var(--dim);font-size:.75rem;text-transform:uppercase}}td{{padding:.4rem .6rem;border-bottom:1px solid rgba(48,54,61,.4)}}td code{{color:var(--acc);font-size:.82rem}}.st-ok{{color:var(--grn);font-weight:600}}.st-denied{{color:var(--red);font-weight:600}}.st-err{{color:var(--org);font-weight:600}}small{{color:var(--dim)}}.fbar{{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center}}.fbar input{{flex:1;min-width:180px;padding:.45rem .8rem;background:var(--card);border:1px solid var(--brd);border-radius:6px;color:var(--tx);font-size:.9rem}}.fbar button{{padding:.4rem .8rem;border:1px solid var(--brd);border-radius:6px;background:var(--card);color:var(--tx);cursor:pointer;font-size:.8rem}}.fbar button:hover{{border-color:var(--acc);color:var(--acc)}}.fbar button.act{{background:var(--acc);color:var(--bg);border-color:var(--acc)}}.finding{{background:var(--card);border:1px solid var(--brd);border-radius:8px;padding:.8rem 1rem;margin-bottom:.5rem}}.sev{{padding:.1rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700;margin-right:.5rem}}.f-svc{{color:var(--acc);font-weight:600;margin-right:.5rem}}.f-res{{color:var(--dim);font-size:.85rem}}.f-title{{margin-top:.3rem;font-weight:600}}.f-detail{{color:var(--dim);font-size:.85rem;margin-top:.2rem}}.f-rec{{color:var(--grn);font-size:.82rem;margin-top:.3rem;font-style:italic}}.loot-src{{color:var(--acc);margin:1rem 0 .5rem;font-size:1rem}}.loot-item{{background:var(--card);border:1px solid var(--brd);border-radius:6px;margin-bottom:.4rem;overflow:hidden}}.loot-hd{{padding:.5rem .8rem;cursor:pointer;font-size:.9rem}}.loot-hd:hover{{background:rgba(88,166,255,.04)}}.loot-bd{{background:var(--bg);margin:.4rem;padding:.8rem;border-radius:4px;font-size:.8rem;max-height:400px;overflow:auto;white-space:pre-wrap;word-break:break-word}}.recon-id{{background:var(--card);border:1px solid var(--brd);border-radius:8px;padding:.8rem 1rem;margin-bottom:1rem}}.recon-row{{display:flex;gap:.8rem;padding:.2rem 0}}.recon-l{{color:var(--dim);min-width:70px;font-size:.8rem;text-transform:uppercase}}.recon-v{{font-weight:600}}.recon-stmt{{margin:.3rem 0 .3rem .5rem;font-size:.85rem}}</style></head><body>
<h1>AWSAULT</h1><div class="sub">AWS Post-Compromise Enumeration Report &mdash; {_esc(mode)}</div>
<div class="grid"><div class="stat"><div class="l">Account</div><div class="v v-a" style="font-size:1rem;word-break:break-all">{_esc(account)}</div></div><div class="stat"><div class="l">ARN</div><div class="v" style="font-size:.8rem;word-break:break-all">{_esc(arn)}</div></div><div class="stat"><div class="l">Region</div><div class="v v-a">{_esc(region)}</div></div><div class="stat"><div class="l">Services</div><div class="v v-a">{svc_count}</div></div><div class="stat"><div class="l">OK / Total</div><div class="v v-g">{total_ok}<span style="color:var(--dim)">/{total_calls}</span></div></div><div class="stat"><div class="l">Denied</div><div class="v v-r">{total_denied}</div></div><div class="stat"><div class="l">Findings</div><div class="v v-r">{finding_count}</div></div><div class="stat"><div class="l">Crit/High</div><div class="v v-r">{crit_count}/{high_count}</div></div><div class="stat"><div class="l">Loot</div><div class="v v-y">{loot_count}</div></div></div>
{tabs}
<div class="panel active" id="panel-services"><div class="fbar"><input type="text" id="svc-search" placeholder="Filter services..." oninput="filterSvc()"><button class="act" id="btn-all" onclick="filterSt('all',this)">All</button><button id="btn-ok" onclick="filterSt('ok',this)">Has Access</button><button id="btn-denied" onclick="filterSt('denied',this)">No Access</button><button onclick="document.querySelectorAll('.card-bd').forEach(e=>e.style.display='block')">Expand</button><button onclick="document.querySelectorAll('.card-bd').forEach(e=>e.style.display='none')">Collapse</button></div>{svc_cards}</div>
<div class="panel" id="panel-findings">{findings_html if findings_html else '<div style="color:var(--dim);padding:2rem;text-align:center">No findings.</div>'}</div>
<div class="panel" id="panel-loot">{loot_html if loot_html else '<div style="color:var(--dim);padding:2rem;text-align:center">No loot collected.</div>'}</div>
<div class="panel" id="panel-recon">{recon_html if recon_html else '<div style="color:var(--dim);padding:2rem;text-align:center">No recon data (run with --godeep).</div>'}</div>
<script>function toggle(el){{const bd=el.nextElementSibling;bd.style.display=bd.style.display==='none'?'block':'none'}}function showTab(id,el){{document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.getElementById('panel-'+id).classList.add('active');el.classList.add('active')}}let stF='all';function filterSvc(){{const q=document.getElementById('svc-search').value.toLowerCase();document.querySelectorAll('.svc-card').forEach(c=>{{const n=c.dataset.name;const s=c.dataset.status;const mt=!q||n.includes(q);const ms=stF==='all'||(stF==='ok'&&s!=='badge-denied')||(stF==='denied'&&s==='badge-denied');c.style.display=(mt&&ms)?'':'none'}})}}function filterSt(f,el){{stF=f;document.querySelectorAll('.fbar button').forEach(b=>b.classList.remove('act'));el.classList.add('act');filterSvc()}}</script></body></html>'''

    with open(filepath, "w") as f:
        f.write(html)
