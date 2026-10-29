"""
Terminal UI components and layout rendering using Rich.
Inspired by modern developer tools (driftctl) with clean borders,
restrained color mapping, and structured panels.
"""

import sys
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Initialize consoles (standard and error)
console = Console()
err_console = Console(stderr=True)

# Risk tier color definitions
TIER_STYLES = {
    "LOW": "bold green",
    "MODERATE": "bold yellow",
    "HIGH": "bold dark_orange",
    "CRITICAL": "bold red",
    "UNKNOWN": "bold white"
}

TIER_BG_STYLES = {
    "LOW": "on green",
    "MODERATE": "on dark_goldenrod",
    "HIGH": "on dark_orange",
    "CRITICAL": "on red",
    "UNKNOWN": "on grey30"
}

DIMENSION_LABELS = {
    "vulnerability": "Known Vulnerabilities",
    "repository_health": "Repository Health",
    "activity": "Project Activity",
    "maintainer": "Maintainer Health",
    "release": "Release Practices",
    "dependency": "Governance Signals"
}

def render_banner(c: Optional[Console] = None):
    """Render compact, modern tool banner."""
    active_console = c or console
    banner_text = Text()
    banner_text.append("Open Source Dependency Risk Analyzer\n", style="bold cyan")
    banner_text.append("Dependency security and health beyond known CVEs", style="dim")
    panel = Panel(
        banner_text,
        box=box.ROUNDED,
        border_style="bright_blue",
        padding=(0, 2)
    )
    active_console.print(panel)

def get_tier_style(tier: str) -> str:
    """Get Rich text style for a risk tier."""
    return TIER_STYLES.get(tier.upper(), "bold white")

def make_progress_bar(normalized_val: float, length: int = 10) -> Text:
    """Generate a compact graphical risk meter e.g. [██████░░░░]."""
    clamped = min(1.0, max(0.0, float(normalized_val)))
    filled_len = int(round(clamped * length))
    empty_len = length - filled_len

    color = "green"
    if clamped >= 0.75:
        color = "red"
    elif clamped >= 0.50:
        color = "dark_orange"
    elif clamped >= 0.25:
        color = "yellow"

    bar = Text()
    bar.append("█" * filled_len, style=f"bold {color}")
    bar.append("░" * empty_len, style="dim white")
    return bar

def render_analysis(
    data: Dict[str, Any],
    duration_sec: Optional[float] = None,
    c: Optional[Console] = None
):
    """Render full driftctl-inspired risk assessment view."""
    active_console = c or console

    # 1. Header Banner
    render_banner(active_console)

    repo_info = data.get("repository", {})
    owner = repo_info.get("owner", "unknown")
    name = repo_info.get("name", "unknown")
    url = repo_info.get("url", f"https://github.com/{owner}/{name}")
    lang = repo_info.get("language") or "Unknown"
    license_name = repo_info.get("license") or "Unlicensed / Unknown"
    archived = repo_info.get("archived", False)
    is_fixture = data.get("is_demo_fixture", False)

    score = data.get("risk_score", 0.0)
    level = data.get("risk_level", "UNKNOWN")
    level_style = get_tier_style(level)
    explanation = data.get("explanation", "")
    analysis_id = data.get("analysis_id", "N/A")
    scoring_ver = data.get("scoring_version", "v0.1")

    # 2. Executive Summary Panel
    mode_text = "[blue]DEMO FIXTURE[/blue]" if is_fixture else "[green]LIVE DATA[/green]"
    archived_text = "[bold red]Archived (Unmaintained)[/bold red]" if archived else "[green]Active[/green]"

    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column("Key", style="dim", justify="right")
    summary_table.add_column("Value")
    summary_table.add_column("Key2", style="dim", justify="right")
    summary_table.add_column("Value2")

    summary_table.add_row(
        "Repository:", f"[bold white]{owner}/{name}[/bold white]",
        "Mode:", mode_text
    )
    summary_table.add_row(
        "Target URL:", f"[dim]{url}[/dim]",
        "Status:", archived_text
    )
    summary_table.add_row(
        "Language:", f"[cyan]{lang}[/cyan]",
        "License:", f"[magenta]{license_name}[/magenta]"
    )
    summary_table.add_row(
        "Risk Rating:", f"[{level_style}]{score:.2f} / 1.00  [{level}][/]",
        "Classification:", f"[{level_style}]{level}[/]"
    )

    active_console.print(
        Panel(
            summary_table,
            title="[bold bright_white]Overview & Target[/bold bright_white]",
            border_style="bright_black",
            box=box.ROUNDED,
            padding=(0, 1)
        )
    )

    # 3. Factor-by-Factor Risk Breakdown Table
    factors = data.get("risk_factors", {})
    factors_items = factors.items() if hasattr(factors, "items") else []

    breakdown_table = Table(
        title="Risk Dimension Breakdown",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold bright_white",
        expand=True
    )

    breakdown_table.add_column("Risk Dimension", style="bright_white", ratio=3)
    breakdown_table.add_column("Raw Signal", justify="right", style="cyan", ratio=2)
    breakdown_table.add_column("Normalized (0-1)", justify="right", ratio=2)
    breakdown_table.add_column("Weight", justify="right", style="dim", ratio=1)
    breakdown_table.add_column("Contribution", justify="right", style="bold", ratio=2)
    breakdown_table.add_column("Risk Meter", justify="center", ratio=2)

    for factor_key, f_data in factors_items:
        dim_label = DIMENSION_LABELS.get(factor_key, factor_key.replace("_", " ").title())
        
        # Safe extraction supporting objects and dicts
        if hasattr(f_data, "raw_value"):
            raw_val = f_data.raw_value
            norm_val = f_data.normalized_value
            weight_val = f_data.weight
            contrib_val = f_data.weighted_contribution
        elif isinstance(f_data, dict):
            raw_val = f_data.get("raw_value", 0.0)
            norm_val = f_data.get("normalized_value", 0.0)
            weight_val = f_data.get("weight", 0.0)
            contrib_val = f_data.get("weighted_contribution", 0.0)
        else:
            raw_val, norm_val, weight_val, contrib_val = 0.0, 0.0, 0.0, 0.0

        raw_str = f"{raw_val:.2f}" if isinstance(raw_val, (int, float)) else str(raw_val)
        norm_float = float(norm_val) if isinstance(norm_val, (int, float)) else 0.0
        weight_float = float(weight_val) if isinstance(weight_val, (int, float)) else 0.0
        contrib_float = float(contrib_val) if isinstance(contrib_val, (int, float)) else 0.0

        meter = make_progress_bar(norm_float, length=10)

        breakdown_table.add_row(
            dim_label,
            raw_str,
            f"{norm_float:.4f}",
            f"{weight_float:.2f}",
            f"{contrib_float:.4f}",
            meter
        )

    active_console.print(breakdown_table)

    # 4. Known Vulnerabilities Table (if present)
    vulns = data.get("vulnerabilities", [])
    if vulns:
        vuln_table = Table(
            title=f"Known Vulnerability Signals ({len(vulns)} reported)",
            box=box.ROUNDED,
            border_style="red",
            header_style="bold bright_white",
            expand=True
        )
        vuln_table.add_column("Advisory ID", style="bold red", ratio=2)
        vuln_table.add_column("Severity", justify="center", ratio=1)
        vuln_table.add_column("CVSS", justify="right", style="cyan", ratio=1)
        vuln_table.add_column("Summary Snippet", ratio=4)
        vuln_table.add_column("Fixed Version", style="green", ratio=2)

        for v in vulns:
            if isinstance(v, dict):
                v_id = v.get("vuln_id", "UNKNOWN")
                sev = v.get("severity", "UNKNOWN")
                cvss = v.get("cvss_score", 0.0)
                summary = v.get("summary", "")[:75]
                fixed = v.get("fixed_versions", "N/A")
            else:
                v_id = getattr(v, "vuln_id", "UNKNOWN")
                sev = getattr(v, "severity", "UNKNOWN")
                cvss = getattr(v, "cvss_score", 0.0)
                summary = getattr(v, "summary", "")[:75]
                fixed = getattr(v, "fixed_versions", "N/A")

            sev_style = get_tier_style(sev)
            vuln_table.add_row(
                v_id,
                f"[{sev_style}]{sev}[/]",
                f"{float(cvss):.1f}" if cvss else "N/A",
                summary,
                fixed or "None available"
            )
        active_console.print(vuln_table)
    else:
        active_console.print("[dim green]✓ No known public OSV advisories reported for this component.[/dim green]\n")

    # 5. Diagnostic Explanation
    active_console.print(
        Panel(
            Text(explanation, style="bright_white"),
            title="[bold bright_white]Diagnostic Assessment[/bold bright_white]",
            border_style=level_style,
            box=box.ROUNDED,
            padding=(0, 2)
        )
    )

    # 6. Data Quality Warnings (if any)
    warnings = data.get("warnings", [])
    if warnings:
        warn_text = Text()
        for w in warnings:
            warn_text.append(f"• {w}\n", style="yellow")
        active_console.print(
            Panel(
                warn_text,
                title="[bold yellow]Data Quality & Collection Notices[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED
            )
        )

    # 7. Compact Footer
    duration_str = f"{duration_sec:.2f}s" if duration_sec is not None else "instant"
    footer_text = f"Analysis ID: [bold white]{analysis_id}[/bold white]  •  Version: [dim]{scoring_ver}[/dim]  •  Duration: [dim]{duration_str}[/dim]"
    active_console.print(Panel(footer_text, border_style="dim", box=box.ROUNDED, padding=(0, 2)))

def render_history(records: List[Any], c: Optional[Console] = None):
    """Render past analysis records in a compact, structured table."""
    active_console = c or console
    render_banner(active_console)

    if not records:
        active_console.print("[yellow]No historical risk analyses found in local database.[/yellow]")
        return

    hist_table = Table(
        title=f"Recent Dependency Risk Analyses ({len(records)} records)",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_white",
        expand=True
    )

    hist_table.add_column("Analysis ID", style="bold cyan", ratio=2)
    hist_table.add_column("Repository", style="bright_white", ratio=3)
    hist_table.add_column("Score", justify="right", ratio=1)
    hist_table.add_column("Risk Tier", justify="center", ratio=2)
    hist_table.add_column("Mode", justify="center", ratio=2)
    hist_table.add_column("Timestamp (UTC)", style="dim", ratio=3)

    for item in records:
        a_id = getattr(item, "analysis_id", "N/A")
        repo = getattr(item, "repository", None)
        repo_name = f"{repo.owner}/{repo.name}" if repo else "Unknown"
        score = getattr(item, "composite_score", 0.0)
        level = getattr(item, "risk_level", "UNKNOWN")
        is_fixture = getattr(item, "is_demo_fixture", False)
        mode_str = "[blue]FIXTURE[/blue]" if is_fixture else "[green]LIVE[/green]"
        ts = getattr(item, "created_at", None)
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"
        level_style = get_tier_style(level)

        hist_table.add_row(
            a_id,
            repo_name,
            f"{score:.2f}",
            f"[{level_style}]{level}[/]",
            mode_str,
            ts_str
        )

    active_console.print(hist_table)

def render_health(health_info: Dict[str, Any], c: Optional[Console] = None):
    """Render backend and integration health status."""
    active_console = c or console
    render_banner(active_console)

    health_table = Table(
        title="System Subsystem Health Status",
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold bright_white",
        expand=True
    )
    health_table.add_column("Subsystem / Component", style="bright_white", ratio=2)
    health_table.add_column("Status", justify="center", ratio=1)
    health_table.add_column("Latency", justify="right", style="cyan", ratio=1)
    health_table.add_column("Details", style="dim", ratio=3)

    for comp in health_info.get("components", []):
        status = comp.get("status", "UNKNOWN")
        style = "bold green" if status == "UP" else ("bold yellow" if status == "DEGRADED" else "bold red")
        latency = f"{comp.get('latency_ms', 0):.1f} ms" if "latency_ms" in comp else "N/A"
        health_table.add_row(
            comp.get("name", "Unknown"),
            f"[{style}]{status}[/]",
            latency,
            comp.get("message", "")
        )

    active_console.print(health_table)

def render_error(title: str, message: str, c: Optional[Console] = None):
    """Render an error message panel."""
    active_console = c or err_console
    active_console.print(
        Panel(
            Text(message, style="bold red"),
            title=f"[bold red]Error: {title}[/bold red]",
            border_style="red",
            box=box.ROUNDED
        )
    )

def render_warning(message: str, c: Optional[Console] = None):
    """Render a warning message."""
    active_console = c or console
    active_console.print(f"[bold yellow]Warning:[/bold yellow] {message}")

def render_success(message: str, c: Optional[Console] = None):
    """Render a success message."""
    active_console = c or console
    active_console.print(f"[bold green]Success:[/bold green] {message}")
