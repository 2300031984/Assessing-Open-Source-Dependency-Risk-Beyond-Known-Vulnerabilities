"""
Main entry point for CYBER-100 CLI application.
Uses Typer for command dispatching and Rich for terminal presentation.
"""

import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
import requests
import typer
from rich.console import Console

# Windows UTF-8 stdout protection
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from backend.app.core.config import settings
from backend.app.database.session import SessionLocal, init_db, engine
from backend.app.models.domain import RiskAssessment, Repository
from backend.app.services.analysis_service import AnalysisService
from backend.app.collectors.github_collector import GitHubCollector
from backend.cli.formatters import serialize_analysis_json, save_report_file
from backend.cli.ui import (
    console,
    err_console,
    render_analysis,
    render_history,
    render_health,
    render_error,
    render_warning,
    render_success,
    render_banner
)

app = typer.Typer(
    name="cyber100-cli",
    help="CYBER-100: Assessing Open Source Dependency Risk Beyond Known Vulnerabilities.",
    no_args_is_help=True,
    add_completion=False
)

CLI_VERSION = "1.0.0"
SCORING_ENGINE_VERSION = "v0.1"


def sanitize_secrets(text: str) -> str:
    """Mask any sensitive API tokens from output strings and error messages."""
    if not text:
        return text
    sanitized = text
    if settings.GITHUB_TOKEN:
        sanitized = sanitized.replace(settings.GITHUB_TOKEN, "***REDACTED***")
    sanitized = re.sub(r"ghp_[A-Za-z0-9_]{36}", "***REDACTED***", sanitized)
    sanitized = re.sub(r"github_pat_[A-Za-z0-9_]{82}", "***REDACTED***", sanitized)
    return sanitized


def normalize_repo_input(repo_input: str) -> str:
    """Normalize user input e.g. 'psf/requests' or 'github.com/psf/requests' to full URL."""
    cleaned = repo_input.strip()
    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        if "/" in cleaned and not cleaned.startswith("github.com/"):
            return f"https://github.com/{cleaned}"
        elif cleaned.startswith("github.com/"):
            return f"https://{cleaned}"
    return cleaned


def version_callback(value: bool):
    """Callback for --version flag."""
    if value:
        console.print(f"CYBER-100 CLI v{CLI_VERSION} (Scoring Engine {SCORING_ENGINE_VERSION})")
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show CLI version and exit.",
        callback=version_callback,
        is_eager=True
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable ANSI color and formatting."
    )
):
    """
    Open Source Dependency Risk Analyzer CLI.
    Evaluates open-source packages across 6 multidimensional risk factors beyond known CVEs.
    """
    if no_color:
        console.no_color = True
        err_console.no_color = True


@app.command(name="analyze")
def analyze(
    repository: str = typer.Argument(
        ...,
        help="Repository in 'owner/repo' or 'https://github.com/owner/repo' format."
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output raw analysis results as formatted JSON."
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save complete analysis report as JSON to specified file path."
    ),
    fixture: bool = typer.Option(
        False,
        "--fixture",
        "--offline",
        help="Use offline deterministic demo fixtures instead of live API collection."
    )
):
    """
    Perform deep multidimensional risk analysis on an open-source repository.
    Calculates risk across vulnerabilities, health, activity, maintainers, releases, and governance.
    """
    # 1. Normalize and validate input
    repo_url = normalize_repo_input(repository)
    try:
        GitHubCollector.parse_github_url(repo_url)
    except ValueError as e:
        safe_msg = sanitize_secrets(str(e))
        render_error("Invalid Repository Format", safe_msg)
        raise typer.Exit(code=2)

    # 2. Prepare database session
    try:
        init_db()
        db = SessionLocal()
    except Exception as e:
        safe_msg = sanitize_secrets(str(e))
        render_error("Database Initialization Failure", safe_msg)
        raise typer.Exit(code=1)

    # 3. Execute analysis
    start_time = time.perf_counter()
    service = AnalysisService(db)

    try:
        if json_output:
            # Silent execution for clean JSON output to stdout
            result = service.analyze_repository(repo_url, use_demo_fixture=fixture)
        else:
            status_msg = (
                "[bold cyan]Running offline demo risk analysis fixture...[/bold cyan]"
                if fixture
                else f"[bold cyan]Collecting signals & OSV advisories for {repo_url}...[/bold cyan]"
            )
            with console.status(status_msg, spinner="dots"):
                result = service.analyze_repository(repo_url, use_demo_fixture=fixture)
    except ValueError as e:
        safe_msg = sanitize_secrets(str(e))
        render_error("Repository Not Found", safe_msg)
        raise typer.Exit(code=1)
    except requests.exceptions.RequestException as e:
        safe_msg = sanitize_secrets(str(e))
        render_error("External Intelligence Failure", safe_msg)
        raise typer.Exit(code=1)
    except Exception as e:
        safe_msg = sanitize_secrets(str(e))
        render_error("Analysis Engine Failure", safe_msg)
        raise typer.Exit(code=1)
    finally:
        db.close()

    elapsed = time.perf_counter() - start_time

    # 4. Handle file report export if requested
    if output:
        try:
            saved_file = save_report_file(result, output)
            if not json_output:
                render_success(f"Report exported successfully to: [bold white]{saved_file}[/bold white]")
        except Exception as e:
            safe_msg = sanitize_secrets(str(e))
            render_error("File Export Error", f"Failed to save report to '{output}': {safe_msg}")
            raise typer.Exit(code=2)

    # 5. Output results
    if json_output:
        json_str = serialize_analysis_json(result)
        # Directly print to standard output without rich decoration
        sys.stdout.write(json_str)
        sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        render_analysis(result, duration_sec=elapsed, c=console)

    raise typer.Exit(code=0)


@app.command(name="history")
def history(
    limit: int = typer.Option(
        10,
        "--limit",
        "-n",
        help="Maximum number of historical analyses to display."
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output history records as formatted JSON."
    )
):
    """
    List recent repository risk analyses stored in the local database.
    """
    try:
        init_db()
        db = SessionLocal()
    except Exception as e:
        render_error("Database Error", sanitize_secrets(str(e)))
        raise typer.Exit(code=1)

    try:
        records = (
            db.query(RiskAssessment)
            .order_by(RiskAssessment.created_at.desc())
            .limit(limit)
            .all()
        )

        if json_output:
            history_data = []
            for r in records:
                repo = r.repository
                history_data.append({
                    "analysis_id": r.analysis_id,
                    "repository": f"{repo.owner}/{repo.name}" if repo else "Unknown",
                    "repository_url": repo.url if repo else None,
                    "risk_score": r.composite_score,
                    "risk_level": r.risk_level,
                    "is_demo_fixture": r.is_demo_fixture,
                    "scoring_version": r.scoring_version,
                    "created_at": r.created_at.isoformat() if r.created_at else None
                })
            sys.stdout.write(serialize_analysis_json({"history": history_data}))
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            render_history(records, c=console)
    finally:
        db.close()

    raise typer.Exit(code=0)


@app.command(name="show")
def show(
    analysis_id: str = typer.Argument(
        ...,
        help="Unique Analysis ID UUID of the assessment to display."
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output analysis record as formatted JSON."
    )
):
    """
    Inspect the detailed results of a previous risk analysis by ID.
    """
    try:
        init_db()
        db = SessionLocal()
    except Exception as e:
        render_error("Database Error", sanitize_secrets(str(e)))
        raise typer.Exit(code=1)

    try:
        service = AnalysisService(db)
        result = service.get_analysis_by_id(analysis_id)
        if not result:
            render_error("Not Found", f"No risk assessment found with ID: '{analysis_id}'.")
            raise typer.Exit(code=2)

        if json_output:
            sys.stdout.write(serialize_analysis_json(result))
            sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            render_analysis(result, c=console)
    finally:
        db.close()

    raise typer.Exit(code=0)


@app.command(name="health")
def health(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output subsystem health diagnostics as formatted JSON."
    )
):
    """
    Verify health, connectivity, and latency of internal database and external intelligence APIs.
    """
    components = []

    # 1. Test Database
    db_start = time.perf_counter()
    try:
        from sqlalchemy import text
        init_db()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db = SessionLocal()
        repo_count = db.query(Repository).count()
        db.close()
        db_latency = (time.perf_counter() - db_start) * 1000
        components.append({
            "name": "Local Database (SQLite)",
            "status": "UP",
            "latency_ms": round(db_latency, 1),
            "message": f"Connected successfully ({repo_count} repositories indexed)"
        })
    except Exception as e:
        db_latency = (time.perf_counter() - db_start) * 1000
        components.append({
            "name": "Local Database (SQLite)",
            "status": "DOWN",
            "latency_ms": round(db_latency, 1),
            "message": sanitize_secrets(str(e))
        })

    # 2. Test GitHub API Rate Limit / Reachability
    gh_start = time.perf_counter()
    try:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CYBER-100-Risk-Collector/1.0"
        }
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

        gh_res = requests.get(
            "https://api.github.com/rate_limit",
            headers=headers,
            timeout=settings.API_TIMEOUT_SECONDS
        )
        gh_latency = (time.perf_counter() - gh_start) * 1000

        if gh_res.status_code == 200:
            rate_info = gh_res.json().get("resources", {}).get("core", {})
            remaining = rate_info.get("remaining", "N/A")
            limit = rate_info.get("limit", "N/A")
            auth_status = "Authenticated" if settings.GITHUB_TOKEN else "Unauthenticated"
            components.append({
                "name": "GitHub REST Intelligence API",
                "status": "UP" if remaining != 0 else "DEGRADED",
                "latency_ms": round(gh_latency, 1),
                "message": f"{auth_status} ({remaining}/{limit} calls remaining)"
            })
        else:
            components.append({
                "name": "GitHub REST Intelligence API",
                "status": "DEGRADED",
                "latency_ms": round(gh_latency, 1),
                "message": f"HTTP {gh_res.status_code} response"
            })
    except Exception as e:
        gh_latency = (time.perf_counter() - gh_start) * 1000
        components.append({
            "name": "GitHub REST Intelligence API",
            "status": "DOWN",
            "latency_ms": round(gh_latency, 1),
            "message": sanitize_secrets(str(e))
        })

    # 3. Test OSV Advisory API
    osv_start = time.perf_counter()
    try:
        osv_res = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": "urllib3", "ecosystem": "PyPI"}},
            timeout=settings.API_TIMEOUT_SECONDS
        )
        osv_latency = (time.perf_counter() - osv_start) * 1000

        if osv_res.status_code == 200:
            components.append({
                "name": "OSV Vulnerability Intelligence API",
                "status": "UP",
                "latency_ms": round(osv_latency, 1),
                "message": "Advisory database online and responsive"
            })
        else:
            components.append({
                "name": "OSV Vulnerability Intelligence API",
                "status": "DEGRADED",
                "latency_ms": round(osv_latency, 1),
                "message": f"HTTP {osv_res.status_code} response"
            })
    except Exception as e:
        osv_latency = (time.perf_counter() - osv_start) * 1000
        components.append({
            "name": "OSV Vulnerability Intelligence API",
            "status": "DOWN",
            "latency_ms": round(osv_latency, 1),
            "message": sanitize_secrets(str(e))
        })

    # Overall status
    overall_status = "UP"
    if any(c["status"] == "DOWN" for c in components):
        overall_status = "DEGRADED"
    if all(c["status"] == "DOWN" for c in components):
        overall_status = "DOWN"

    health_info = {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": components
    }

    if json_output:
        sys.stdout.write(serialize_analysis_json(health_info))
        sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        render_health(health_info, c=console)

    exit_code = 0 if overall_status in ("UP", "DEGRADED") else 1
    raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
