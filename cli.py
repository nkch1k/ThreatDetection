#!/usr/bin/env python3
"""
CLI tool for IP Threat Intelligence Analysis
"""

import click
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import sys

console = Console()


@click.command()
@click.option('--ip', required=True, help='IP address to analyze')
@click.option('--api-url', default='http://localhost:8000', help='API base URL')
def analyze(ip: str, api_url: str):
    """
    Analyze an IP address for threats and display results.

    Example:
        python cli.py --ip 8.8.8.8
    """
    try:
        with console.status(f"[bold cyan]Analyzing IP: {ip}...", spinner="dots"):
            response = httpx.get(
                f"{api_url}/api/analyze-ip",
                params={"ip": ip},
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()

        # Display results
        display_results(data, ip)

    except httpx.HTTPStatusError as e:
        console.print(f"[bold red]Error:[/bold red] {e.response.status_code}")
        if e.response.status_code == 400:
            console.print(f"[yellow]{e.response.json().get('detail', 'Invalid IP address')}[/yellow]")
        elif e.response.status_code == 503:
            console.print("[yellow]Threat intelligence services are currently unavailable[/yellow]")
        else:
            console.print(f"[yellow]{e.response.text}[/yellow]")
        sys.exit(1)
    except httpx.RequestError:
        console.print(f"[bold red]Connection Error:[/bold red] Cannot connect to API at {api_url}")
        console.print(f"[yellow]Make sure the FastAPI server is running: uvicorn app.main:app[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected Error:[/bold red] {str(e)}")
        sys.exit(1)


def display_results(data: dict, ip: str):
    """Display threat analysis results in a formatted way"""

    threat_data = data.get("threat_data", {})
    ai_analysis = data.get("ai_analysis", {})
    cached = data.get("cached", False)

    # Header
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]IP Threat Intelligence Analysis[/bold cyan]\n"
        f"IP Address: [bold]{ip}[/bold]\n"
        f"Cached: {'[green]Yes[/green]' if cached else '[yellow]No[/yellow]'}",
        box=box.DOUBLE
    ))
    console.print()

    # Threat Data Table
    table = Table(title="Threat Intelligence Data", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value", style="white")

    table.add_row("Hostname", threat_data.get("hostname") or "N/A")
    table.add_row("ISP", threat_data.get("isp") or "N/A")
    table.add_row("Country", threat_data.get("country") or "N/A")
    table.add_row("Abuse Score", f"{threat_data.get('abuse_score') or 'N/A'}/100")
    table.add_row("Recent Reports", str(threat_data.get("recent_reports") or "N/A"))

    vpn = threat_data.get("vpn_detected")
    vpn_text = "[red]Yes[/red]" if vpn else "[green]No[/green]" if vpn is not None else "Unknown"
    table.add_row("VPN Detected", vpn_text)

    proxy = threat_data.get("proxy_detected")
    proxy_text = "[red]Yes[/red]" if proxy else "[green]No[/green]" if proxy is not None else "Unknown"
    table.add_row("Proxy Detected", proxy_text)

    table.add_row("Fraud Score", f"{threat_data.get('fraud_score') or 'N/A'}/100")

    tor = threat_data.get("is_tor")
    tor_text = "[red]Yes[/red]" if tor else "[green]No[/green]" if tor is not None else "Unknown"
    table.add_row("Tor Exit Node", tor_text)

    console.print(table)
    console.print()

    # Risk Level Panel
    risk_level = ai_analysis.get("risk_level", "Unknown")
    risk_color = "green" if risk_level == "Low" else "yellow" if risk_level == "Medium" else "red"

    console.print(Panel(
        f"[bold {risk_color}]{risk_level.upper()} RISK[/bold {risk_color}]",
        title="Risk Assessment",
        box=box.HEAVY,
        expand=False
    ))
    console.print()

    # AI Analysis
    analysis_text = ai_analysis.get("risk_analysis", "No analysis available")
    console.print(Panel(
        analysis_text,
        title="[bold]AI Risk Analysis[/bold]",
        border_style="blue",
        box=box.ROUNDED
    ))
    console.print()

    # Recommendations
    recommendations = ai_analysis.get("recommendations", [])
    if recommendations:
        console.print("[bold cyan]Security Recommendations:[/bold cyan]")
        for i, rec in enumerate(recommendations, 1):
            console.print(f"  {i}. {rec}")
        console.print()


if __name__ == "__main__":
    analyze()
