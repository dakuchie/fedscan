r"""Statistics and figures for the manuscript. Every number in the Results section is produced here.

    python analyze.py --scan data/scan.jsonl --meta data/repos/repos.csv \
                      [--labels data/labels.csv] [--disclosure data/disclosure.csv] --out ../manuscript

Outputs:
  <out>/figures/*.pdf          figures referenced by main.tex
  <out>/generated/results.tex  \newcommand macros (\NumBindings, \PctTOne, ...) consumed by main.tex
  <out>/generated/*.tex        LaTeX tables
  data/release/*.csv           pseudonymised dataset for the artifact (PSEUDONYM_KEY env var)

labels.csv     (manual validation sample): binding_id, rater1, rater2, adjudicated   (codes: T1..H4 or OK)
disclosure.csv : repo, binding_id, channel, notified_at, acknowledged_at, fixed_at, outcome
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402
from statsmodels.stats.proportion import proportion_confint  # noqa: E402
import statsmodels.formula.api as smf  # noqa: E402

T_CODES = ["T1", "T2", "T3", "T4", "T5"]
S_CODES = ["S1", "S2"]
H_CODES = ["H1", "H2", "H3", "H4"]
PROVIDER_LABEL = {"aws": "AWS", "azure": "Azure", "gcp": "Google Cloud"}
# Colour-blind-safe palette (Okabe-Ito)
COL = {"aws": "#E69F00", "azure": "#0072B2", "gcp": "#009E73",
       "critical": "#B2182B", "high": "#EF8A62", "medium": "#FDDBC7", "low": "#D1E5F0"}
AWS_GUARDRAIL = pd.Timestamp("2025-06-01", tz="UTC")       # AWS blocks new roles lacking `sub` (Datadog, 2025)
GH_IMMUTABLE = pd.Timestamp("2026-07-15", tz="UTC")        # GitHub immutable subjects default (Microsoft docs)

plt.rcParams.update({"font.family": "serif", "font.size": 9, "axes.spines.top": False,
                     "axes.spines.right": False, "figure.dpi": 300})


# --------------------------------------------------------------------------- loading
def load(scan_path: str, meta_path: str) -> pd.DataFrame:
    rows = []
    with open(scan_path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            d = json.loads(line)
            codes = [x["flaw"] for x in d["findings"]]
            sev = {x["flaw"]: x["severity"] for x in d["findings"]}
            rows.append({
                "binding_id": i, "repo": d["repo"], "provider": d["provider"], "iac": d["iac"],
                "issuer": d.get("issuer"), "file": d["file"], "resource": d["resource"],
                "via_module": bool(d.get("via_module")), "unresolved": d.get("cond_unresolved", False),
                "example_path": d.get("path_is_example", False), "file_added": d.get("file_added"),
                "max_severity": d.get("max_severity"), "scope": d.get("scope", "ci"),
                **{c: c in codes for c in T_CODES + S_CODES + H_CODES + ["U"]},
                **{f"sev_{c}": sev.get(c) for c in T_CODES},
                "sub_values": [v for c in d["conditions"] if c["claim"] == "sub" for v in c["values"]],
                "cel": " ".join(v for c in d["conditions"] if c["claim"] == "__cel__" for v in c["values"]),
                "wild_id": any(x["flaw"] == "H3" and "wildcarded" in x.get("message", "") for x in d["findings"]),
                "sev_S2": sev.get("S2"),
            })
    df = pd.DataFrame(rows)
    meta = pd.read_csv(meta_path).drop_duplicates("repo")
    df = df.merge(meta, on="repo", how="left")
    df["file_added"] = pd.to_datetime(df["file_added"], utc=True, errors="coerce")
    df["platform"] = df["issuer"].map(_platform)
    df["T_any"] = df[T_CODES].any(axis=1)
    # "exploitable" = class-T finding rated critical/high after mitigations (GCP IAM layer, issuer tenancy)
    df["T_crit"] = df[[f"sev_{c}" for c in T_CODES]].isin(["critical", "high"]).any(axis=1)
    df["T_crit_tool"] = df["T_crit"]          # FedScan's verdict before manual adjudication
    df["manual_verdict"] = None
    # Manual verdicts (data/manual_verdicts.csv): bindings whose exposure was checked by hand against the
    # repository, e.g. protections that live outside IaC. 'mitigated' clears the exploitable flag.
    mv_path = Path(scan_path).parent / "manual_verdicts.csv"
    if mv_path.exists():
        mv = pd.read_csv(mv_path)
        for _, v in mv.iterrows():
            hit = (df.repo == v.repo) & (df.file.str.replace("/", "\\") == str(v.file).replace("/", "\\")) & \
                  (df.resource == v.resource)
            df.loc[hit, "manual_verdict"] = v.verdict
            if v.verdict in ("mitigated", "not_exploitable", "false_positive"):
                df.loc[hit, "T_crit"] = False
    df["S_any"] = df[S_CODES].any(axis=1)
    return df


def _platform(iss) -> str:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))
    from fedscan.issuers import platform_of
    return platform_of(iss)


def _pfmt(p: float) -> str:
    """p-value for inline math: 'p < 0.001' or 'p = 0.016' (same rule as the tables)."""
    return "p < 0.001" if p < 0.001 else f"p = {p:.3f}"


def wilson(k: int, n: int) -> tuple[float, float, float]:
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    lo, hi = proportion_confint(k, n, alpha=0.05, method="wilson")
    return k / n, lo, hi


def cramers_v(table: pd.DataFrame) -> float:
    chi2 = stats.chi2_contingency(table, correction=False)[0]
    n = table.values.sum()
    r, k = table.shape
    return float(np.sqrt(chi2 / (n * (min(r, k) - 1))))


# --------------------------------------------------------------------------- analyses
class Macros:
    def __init__(self):
        self.lines: list[str] = []

    _DIGITS = str.maketrans({"0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four", "5": "Five"})

    def add(self, name: str, value) -> None:
        # LaTeX control words cannot contain digits: \PctT1 -> \PctTOne
        name = name.translate(self._DIGITS)
        if isinstance(value, float):
            value = f"{value:.1f}"
        self.lines.append(f"\\newcommand{{\\{name}}}{{{value}}}")

    def pct(self, name: str, k: int, n: int) -> None:
        p, lo, hi = wilson(k, n)
        self.add(name, f"{100*p:.1f}\\%")
        self.add(name + "CI", f"{100*lo:.1f}--{100*hi:.1f}\\%")


def corpus(df: pd.DataFrame, a, m: Macros, out: Path) -> None:
    if a.candidates and Path(a.candidates).exists():
        with open(a.candidates, encoding="utf-8") as f:
            m.add("NumCandidateFiles", f"{sum(1 for _ in f):,}")
    if a.snapshot:
        m.add("SnapshotDate", a.snapshot)
    err_path = Path(a.scan + ".errors")
    if err_path.exists():
        with open(err_path, encoding="utf-8") as f:
            errs = [json.loads(line) for line in f if '"error"' in line]
        n_tmpl = sum(1 for e in errs if e["error"].startswith("TEMPLATE:"))
        n_err = len(errs) - n_tmpl
        n_files = sum(1 for p in Path(a.dest).rglob("*") if p.suffix in (".tf", ".tofu")) if a.dest else 0
        n_files -= n_tmpl
        m.add("NumTemplateFiles", f"{n_tmpl:,}")
        m.add("NumParseErrors", f"{n_err:,}")
        m.add("NumIaCFiles", f"{n_files:,}")
        m.add("PctParseErrors", f"{100 * n_err / max(n_files, 1):.1f}\\%")
    tab = (df.assign(Set=np.where(df.example_path, "example", "production"))
             .groupby(["provider", "iac", "platform", "Set"]).size().unstack("Set", fill_value=0)
             .reset_index())
    tab["provider"] = tab["provider"].map(PROVIDER_LABEL)
    tab["iac"] = tab["iac"].map({"terraform": "Terraform", "cloudformation": "CloudFormation"}).fillna(tab["iac"])
    tab.columns = [{"iac": "IaC"}.get(str(c), str(c).capitalize()) for c in tab.columns]
    tab.to_latex(out / "generated" / "tab_corpus.tex", index=False, escape=True)


def rq1_prevalence(df: pd.DataFrame, m: Macros, out: Path) -> None:
    base = df[~df.example_path]
    m.add("NumBindings", f"{len(df):,}")
    m.add("NumBindingsProd", f"{len(base):,}")
    m.add("NumRepos", f"{df.repo.nunique():,}")
    m.add("NumReposProd", f"{base.repo.nunique():,}")
    m.pct("PctTAny", int(base.T_any.sum()), len(base))
    m.pct("PctTCrit", int(base.T_crit.sum()), len(base))
    m.pct("PctUnresolved", int(base.U.sum()), len(base))
    repo_crit = base.groupby("repo").T_crit.any()
    m.pct("PctReposCrit", int(repo_crit.sum()), len(repo_crit))
    for c in T_CODES + S_CODES + H_CODES:
        m.pct(f"Pct{c}", int(base[c].sum()), len(base))
        m.add(f"Num{c}", f"{int(base[c].sum()):,}")
    m.add("NumTCrit", f"{int(base.T_crit.sum()):,}")
    m.add("NumTCritTool", f"{int(base.T_crit_tool.sum()):,}")
    m.add("NumManualMitigated", f"{int((base.manual_verdict == 'mitigated').sum()):,}")
    m.pct("PctSAny", int(base.S_any.sum()), len(base))
    m.add("NumSAny", f"{int(base.S_any.sum()):,}")
    m.add("NumU", f"{int(base.U.sum()):,}")
    repo_s = base.groupby("repo").S_any.any()
    m.pct("PctReposS", int(repo_s.sum()), len(repo_s))
    # H3 variant: GitHub immutable-subject IDs wildcarded (evidence recorded by the analyzer)
    m.add("NumWildID", f"{int(base.get('wild_id', pd.Series(dtype=bool)).sum()):,}")

    # Table: prevalence by provider
    rows = []
    shown = [c for c in T_CODES if base[c].any()] + S_CODES  # T-codes never observed are noted in the caption
    for prov, g in base.groupby("provider"):
        r = {"Provider": PROVIDER_LABEL.get(prov, prov), "Bindings": len(g), "Repos": g.repo.nunique()}
        for c in shown:
            p, lo, hi = wilson(int(g[c].sum()), len(g))
            r[c] = f"{100*p:.1f}"
        p, lo, hi = wilson(int(g.T_crit.sum()), len(g))
        r["Exploitable (95\\% CI)"] =f"{100*p:.1f} [{100*lo:.1f}, {100*hi:.1f}]"
        rows.append(r)
    pd.DataFrame(rows).to_latex(out / "generated" / "tab_prevalence.tex", index=False, escape=False,
                                column_format="l" + "r" * (len(rows[0]) - 1) if rows else "l")

    # Chi-square: provider x outcome. With < 10 exploitable bindings the test is uninformative, so the
    # provider comparison is made on intra-tenant over-breadth (S-class) instead.
    outcome = "T_crit" if int(base.T_crit.sum()) >= 10 else "S_any"
    m.add("ChiOutcome", "cross-tenant exploitability" if outcome == "T_crit" else "intra-tenant over-breadth")
    tab = pd.crosstab(base.provider, base[outcome])
    if tab.shape == (len(tab.index), 2) and len(tab.index) > 1:
        chi2, p, dof, _ = stats.chi2_contingency(tab)
        m.add("ChiProvider", f"\\chi^2({dof}) = {chi2:.2f}")
        m.add("PChiProvider", "p < 0.001" if p < 0.001 else f"p = {p:.3f}")
        m.add("CramerProvider", f"{cramers_v(tab):.2f}")

    # Figure 1: exploitable share by provider with Wilson CIs
    fig, ax = plt.subplots(figsize=(3.6, 2.4))
    provs = sorted(base.provider.unique())
    x = np.arange(len(provs))
    for k, (col, label, colour) in enumerate([("T_crit", "Cross-tenant (T)", COL["critical"]),
                                               ("S_any", "Over-broad scope (S)", COL["high"])]):
        vals = [wilson(int(base[base.provider == p][col].sum()), int((base.provider == p).sum())) for p in provs]
        ax.bar(x + (k - 0.5) * 0.38, [100 * v[0] for v in vals], width=0.38, color=colour, label=label,
               yerr=[[max(0.0, 100 * (v[0] - v[1])) for v in vals], [max(0.0, 100 * (v[2] - v[0])) for v in vals]],
               capsize=2)
    ax.set_xticks(x, [f"{PROVIDER_LABEL[p]}\n(n={int((base.provider == p).sum())})" for p in provs])
    ax.set_ylabel("Production bindings (%)")
    ax.legend(frameon=False, fontsize=7)
    fig.tight_layout()
    fig.savefig(out / "figures" / "fig_prevalence_provider.pdf")
    plt.close(fig)

    # Figure 2: flaw-class composition by provider (stacked horizontal bars)
    fig, ax = plt.subplots(figsize=(7, 2.2))
    codes = T_CODES + S_CODES
    cmap = plt.get_cmap("RdYlBu")
    left = np.zeros(len(provs))
    for i, c in enumerate(codes):
        share = np.array([100 * base[base.provider == p][c].mean() for p in provs])
        ax.barh([PROVIDER_LABEL[p] for p in provs], share, left=left, label=c,
                color=cmap(i / (len(codes) - 1)), edgecolor="white", linewidth=0.5)
        left += share
    ax.set_xlabel("Share of bindings (%) - a binding carries at most one T/S code")
    ax.legend(ncol=len(codes), loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False)
    fig.tight_layout()
    fig.savefig(out / "figures" / "fig_flaw_composition.pdf")
    plt.close(fig)

    # Figure 3: CI platform x flaw heat map
    plat = base.groupby("platform")[T_CODES + S_CODES].mean().mul(100)
    plat = plat[base.groupby("platform").size() >= 30]  # suppress tiny cells
    if not plat.empty:
        fig, ax = plt.subplots(figsize=(4.5, 0.4 + 0.35 * len(plat)))
        im = ax.imshow(plat.values, cmap="Reds", aspect="auto", vmin=0)
        ax.set_xticks(range(plat.shape[1]), plat.columns)
        ax.set_yticks(range(plat.shape[0]), plat.index)
        for (i, j), v in np.ndenumerate(plat.values):
            ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=7)
        fig.colorbar(im, ax=ax, label="% of bindings")
        fig.tight_layout()
        fig.savefig(out / "figures" / "fig_platform_heatmap.pdf")
        plt.close(fig)


SCOPE_PATTERNS = [
    # (label, predicate over one subject value) - evaluated in order, first match wins
    ("HCP Terraform: any workspace/project in organisation",
     lambda v: v.startswith("organization:") and bool(re.search(r":(project|workspace):\*", v))),
    ("HCP Terraform: any run phase", lambda v: v.startswith("organization:") and v.endswith("run_phase:*")),
    ("CircleCI: any user of a project", lambda v: bool(re.match(r"^org/[^/]+/project/[^/]+/user/\*$", v))),
    ("Any repository in owner (repo:owner/*)", lambda v: bool(re.match(r"^repo:[^/*?]+/\*", v))),
    ("Tag or branch name prefix (e.g. refs/tags/v*)", lambda v: bool(re.search(r":ref:refs/(tags|heads)/[^*]+\*$", v))),
    ("Custom subject template with wildcard", lambda v: v.startswith("repo:") and ":job_workflow_ref:" in v and "*" in v),
    ("Any context of a repository (repo:owner/name:*)", lambda v: bool(re.match(r"^repo:[^/]+/[^:*?]+:\*$", v))),
    ("Any branch (ref:refs/heads/*)", lambda v: ":ref:refs/heads/*" in v),
    ("Any tag (ref:refs/tags/*)", lambda v: ":ref:refs/tags/*" in v),
    ("Any environment (environment:*)", lambda v: ":environment:*" in v),
    ("Pull requests admitted (pull_request)", lambda v: v.endswith(":pull_request")),
    ("Repository without context (exact name only)", lambda v: bool(re.match(r"^repo:[^/:]+/[^:]+$", v))),
]


def scope_pattern(values: list[str], cel: str) -> str:
    if cel and not values:
        return "Google CEL condition (owner or repository only)"
    for label, pred in SCOPE_PATTERNS:
        if any(pred(v) for v in values):
            return label
    return "Other (partly unresolved values)"


def scope_patterns(df: pd.DataFrame, m: Macros, out: Path) -> None:
    s = df[~df.example_path & df.S_any].copy()
    if s.empty:
        return
    s["pattern"] = [scope_pattern(v, c) for v, c in zip(s.sub_values, s.cel)]
    counts = s.pattern.value_counts()
    for i, (label, n) in enumerate(counts.items()):
        m.add(f"ScopePat{'ABCDEFGHIJ'[i]}", label.replace("_", "\\_"))
        m.add(f"ScopePat{'ABCDEFGHIJ'[i]}N", f"{n}")
    fig, ax = plt.subplots(figsize=(6.0, 0.35 + 0.32 * len(counts)))
    ax.barh(counts.index[::-1], counts.values[::-1], color=COL["high"])
    for y, v in enumerate(counts.values[::-1]):
        ax.text(v + 0.3, y, str(v), va="center", fontsize=7)
    ax.set_xlabel(f"Over-broad production bindings (n={len(s)})")
    fig.tight_layout()
    fig.savefig(out / "figures" / "fig_scope_patterns.pdf")
    plt.close(fig)


def rq3_factors(df: pd.DataFrame, m: Macros, out: Path) -> None:
    base = df[~df.example_path & ~df.U].copy()
    base["log_stars"] = np.log1p(base["stars"].fillna(0))
    base["org_owner"] = (base["owner_type"] == "Organization").astype(int)
    base["module"] = base["via_module"].astype(int)
    # Logistic regression needs events: with fewer than 10 exploitable bindings (rare-event regime) the
    # model is fitted to intra-tenant over-breadth (S-class) instead, which is the common failure.
    if int(base["T_crit"].sum()) >= 10:
        base["y"] = base["T_crit"].astype(int)
        m.add("LogitOutcome", "cross-tenant exploitability (T-class, critical/high)")
    else:
        base["y"] = base["S_any"].astype(int)
        m.add("LogitOutcome", "intra-tenant over-breadth (S1 or S2)")
    base["added_year"] = base["file_added"].dt.year
    # Cluster-robust SEs by repository: bindings in one repo are not independent.
    # Terms without variation in this corpus (e.g. owner type unavailable from Sourcegraph) are dropped.
    # Drop terms too sparse to estimate (minority level < 10 bindings), which otherwise cause separation.
    def enough(col) -> bool:
        vc = base[col].value_counts()
        return len(vc) > 1 and vc.min() >= 10
    terms = []
    if enough("provider"):
        terms.append("C(provider)")
    if enough("iac"):
        terms.append("C(iac)")
    for t in ("module", "org_owner"):
        if enough(t):
            terms.append(t)
    if base["log_stars"].nunique() > 10:
        terms.append("log_stars")
    if not terms or base["y"].nunique() < 2:
        return
    m.add("LogitTerms", ", ".join(t.replace("C(", "").replace(")", "").replace("_", r"\_") for t in terms))
    model = smf.logit("y ~ " + " + ".join(terms), data=base)
    res = model.fit(disp=False, cov_type="cluster", cov_kwds={"groups": pd.factorize(base["repo"])[0]})
    ors = pd.DataFrame({"OR": np.exp(res.params), "CI low": np.exp(res.conf_int()[0]),
                        "CI high": np.exp(res.conf_int()[1]), "p": res.pvalues})
    pretty = {"Intercept": "Intercept", "C(provider)[T.azure]": "Azure (vs.\\ AWS)",
              "C(provider)[T.gcp]": "Google Cloud (vs.\\ AWS)", "C(iac)[T.terraform]": "Terraform (vs.\\ CloudFormation)",
              "log_stars": "$\\log(1+\\text{stars})$", "module": "Community module", "org_owner": "Organisation owner"}
    tab = ors.copy()
    tab.index = [pretty.get(i, i.replace("_", "\\_")) for i in tab.index]
    tab["95\\% CI"] = [f"[{lo:.2f}, {hi:.2f}]" for lo, hi in zip(tab["CI low"], tab["CI high"])]
    tab["$p$"] = ["$<$0.001" if p < 0.001 else f"{p:.3f}" for p in tab["p"]]
    tab["OR"] = tab["OR"].map(lambda v: f"{v:.2f}")
    tab[["OR", "95\\% CI", "$p$"]].to_latex(out / "generated" / "tab_logit.tex", escape=False,
                                           column_format="lrrr")
    m.add("LogitN", f"{int(res.nobs):,}")
    m.add("LogitPseudoR", f"{res.prsquared:.3f}")
    for name in ors.index:
        if name.startswith("C(provider)"):
            lvl = name.split("T.")[-1].rstrip("]")
            key = "ORProv" + {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}.get(lvl, lvl)
            m.add(key, f"{ors.loc[name, 'OR']:.2f}")
            m.add(key + "CI", f"[{ors.loc[name, 'CI low']:.2f}, {ors.loc[name, 'CI high']:.2f}]")
            m.add(key + "P", _pfmt(ors.loc[name, 'p']))
        if name.startswith("C(iac)"):
            m.add("ORIaC", f"{ors.loc[name, 'OR']:.2f}")
            m.add("ORIaCCI", f"[{ors.loc[name, 'CI low']:.2f}, {ors.loc[name, 'CI high']:.2f}]")
            m.add("ORIaCP", _pfmt(ors.loc[name, 'p']))
    if "log_stars" in ors.index:
        m.add("ORStars", f"{ors.loc['log_stars', 'OR']:.2f}")
        m.add("ORStarsCI", f"[{ors.loc['log_stars', 'CI low']:.2f}, {ors.loc['log_stars', 'CI high']:.2f}]")
        m.add("ORStarsP", _pfmt(ors.loc['log_stars', 'p']))
    if "module" in ors.index:
        m.add("ORModule",f"{ors.loc['module', 'OR']:.2f}")
        m.add("ORModuleCI", f"[{ors.loc['module', 'CI low']:.2f}, {ors.loc['module', 'CI high']:.2f}]")


def rq4_temporal(df: pd.DataFrame, m: Macros, out: Path) -> None:
    aws = df[(df.provider == "aws") & ~df.example_path & df.file_added.notna() & ~df.unresolved].copy()
    if aws.empty:
        return
    aws["month"] = aws.file_added.dt.tz_convert(None).dt.to_period("M").dt.to_timestamp()
    monthly = aws.groupby("month").agg(n=("T1", "size"), t1=("T1", "sum")).query("n >= 10")
    monthly["share"] = 100 * monthly.t1 / monthly.n
    before = aws[aws.file_added < AWS_GUARDRAIL]
    after = aws[aws.file_added >= AWS_GUARDRAIL]
    m.pct("PctTOneBefore", int(before.T1.sum()), len(before))
    m.pct("PctTOneAfter", int(after.T1.sum()), len(after))
    if len(before) and len(after):
        table = [[int(before.T1.sum()), len(before) - int(before.T1.sum())],
                 [int(after.T1.sum()), len(after) - int(after.T1.sum())]]
        odds, p = stats.fisher_exact(table)
        m.add("FisherGuardrailOR", f"{odds:.2f}")
        m.add("FisherGuardrailP", "p < 0.001" if p < 0.001 else f"p = {p:.3f}")
    # Segmented (interrupted time-series) regression on monthly share
    if len(monthly) >= 12:
        ts = monthly.reset_index()
        ts["t"] = np.arange(len(ts))
        ts["post"] = (ts["month"] >= AWS_GUARDRAIL.tz_convert(None)).astype(int)
        ts["t_post"] = ts["t"] * ts["post"]
        its = smf.wls("share ~ t + post + t_post", data=ts, weights=ts["n"]).fit()
        m.add("ITSLevelChange", f"{its.params.get('post', float('nan')):.1f}")
        m.add("ITSLevelP", f"{its.pvalues.get('post', float('nan')):.3f}")
    fig, ax = plt.subplots(figsize=(7, 2.2))
    ax.plot(monthly.index, monthly.share, marker="o", ms=2, color=COL["aws"])
    ax.axvline(AWS_GUARDRAIL.tz_convert(None), ls="--", color="grey", lw=0.8)
    ax.text(AWS_GUARDRAIL.tz_convert(None), ax.get_ylim()[1] * 0.95, " AWS guardrail", fontsize=7, va="top")
    ax.set_ylabel("New AWS bindings\nmissing sub (T1, %)")
    fig.tight_layout()
    fig.savefig(out / "figures" / "fig_temporal_aws.pdf")
    plt.close(fig)


def rq5_disclosure(path: str | None, m: Macros, out: Path) -> None:
    if not path or not Path(path).exists():
        return
    d = pd.read_csv(path, parse_dates=["notified_at", "acknowledged_at", "fixed_at"])
    m.add("NumNotified", f"{len(d):,}")
    m.pct("PctAcked", int(d.acknowledged_at.notna().sum()), len(d))
    m.pct("PctFixed", int(d.fixed_at.notna().sum()), len(d))
    try:
        from lifelines import KaplanMeierFitter
    except ImportError:
        return
    end = d.notified_at.max() + pd.Timedelta(days=90)
    d["duration"] = (d.fixed_at.fillna(end) - d.notified_at).dt.days.clip(lower=0)
    d["event"] = d.fixed_at.notna().astype(int)
    kmf = KaplanMeierFitter()
    fig, ax = plt.subplots(figsize=(3.4, 2.4))
    for ch, g in d.groupby("channel"):
        kmf.fit(g.duration, g.event, label=str(ch))
        kmf.plot_survival_function(ax=ax, ci_show=True)
    kmf.fit(d.duration, d.event)
    med = kmf.median_survival_time_
    m.add("MedianDaysToFix", "not reached" if np.isinf(med) else f"{med:.0f}")
    ax.set_xlabel("Days since notification")
    ax.set_ylabel("Share still vulnerable")
    fig.tight_layout()
    fig.savefig(out / "figures" / "fig_km_remediation.pdf")
    plt.close(fig)


def rq6_validation(df: pd.DataFrame, path: str | None, m: Macros, out: Path) -> None:
    if not path or not Path(path).exists():
        return
    from sklearn.metrics import cohen_kappa_score
    lab = pd.read_csv(path)
    m.add("NumLabelled", f"{len(lab):,}")
    m.add("Kappa", f"{cohen_kappa_score(lab.rater1, lab.rater2):.2f}")
    merged = lab.merge(df[["binding_id", "T_crit"]], on="binding_id")
    truth = merged.adjudicated.isin(T_CODES)
    pred = merged.T_crit
    tp, fp, fn = int((truth & pred).sum()), int((~truth & pred).sum()), int((truth & ~pred).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    m.add("Precision", f"{100*prec:.1f}\\%")
    m.add("Recall", f"{100*rec:.1f}\\%")
    m.add("FOne", f"{2*prec*rec/(prec+rec):.2f}" if prec + rec else "n/a")


def release(df: pd.DataFrame, path: Path) -> None:
    key = os.environ.get("PSEUDONYM_KEY", "").encode()
    if not key:
        print("PSEUDONYM_KEY not set; skipping pseudonymised release export")
        return
    pub = df.drop(columns=["file", "resource"]).copy()
    pub["repo"] = pub["repo"].map(lambda r: hmac.new(key, str(r).encode(), hashlib.sha256).hexdigest()[:16])
    path.mkdir(parents=True, exist_ok=True)
    pub.to_csv(path / "bindings.csv", index=False)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--labels")
    ap.add_argument("--disclosure")
    ap.add_argument("--candidates", help="candidates.jsonl from collect.py search")
    ap.add_argument("--dest", help="repository directory (to count Terraform files for the parse-error rate)")
    ap.add_argument("--snapshot", help="date of the code search, e.g. '15 November 2026'")
    ap.add_argument("--out", default="../manuscript")
    a = ap.parse_args()
    out = Path(a.out)
    (out / "figures").mkdir(parents=True, exist_ok=True)
    (out / "generated").mkdir(parents=True, exist_ok=True)
    df = load(a.scan, a.meta)
    m = Macros()
    # Study scope: CI/CD issuers only. Kubernetes service-account (IRSA/AKS/GKE) and Cognito bindings use the
    # same cloud mechanism but a different trust model; bindings whose issuer could not be resolved and whose
    # conditions show no CI grammar are reported but excluded.
    m.add("NumBindingsAll", f"{len(df):,}")
    m.add("NumNonCI", f"{int((df.scope == 'non_ci').sum()):,}")
    m.add("NumScopeUnknown", f"{int((df.scope == 'unknown').sum()):,}")
    # Sensitivity bound: unknown-scope production bindings that would be T1 if their (unresolved) issuer
    # were a shared CI issuer. Upper bound = (confirmed exploitable + these) / (CI prod + these).
    unk = df[(df.scope == "unknown") & ~df.example_path & df.T1 & ~df.U]
    ci_prod = df[(df.scope == "ci") & ~df.example_path]
    m.add("NumUnknownTOne", f"{len(unk):,}")
    m.add("NumUnknownTOneRepos", f"{unk.repo.nunique():,}")
    m.pct("PctTCritUpper", int(ci_prod.T_crit.sum()) + len(unk), len(ci_prod) + len(unk))
    df = df[df.scope == "ci"].reset_index(drop=True)
    corpus(df, a, m, out)
    rq1_prevalence(df, m, out)
    scope_patterns(df, m, out)
    rq3_factors(df, m, out)
    rq4_temporal(df, m, out)
    rq5_disclosure(a.disclosure, m, out)
    rq6_validation(df, a.labels, m, out)
    (out / "generated" / "results.tex").write_text("\n".join(m.lines) + "\n", encoding="utf-8")
    release(df, Path(a.scan).parent / "release")
    print(f"wrote {len(m.lines)} macros")


if __name__ == "__main__":
    main()
