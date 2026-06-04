# utils/display.py
# handles ALL terminal output — every module imports from here

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def print_banner():
    banner = """
  ██████╗ ███████╗███████╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██║ ██╔╝
  ██████╔╝█████╗  █████╗  █████╔╝ 
  ██╔═══╝ ██╔══╝  ██╔══╝  ██╔═██╗ 
  ██║     ███████╗███████╗██║  ██╗
  ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝"""

    console.print(Panel(
        Text(banner, style="bold magenta", justify="center"),
        subtitle="[dim italic]look before you leap[/dim italic]",
        border_style="magenta",
        box=box.ROUNDED
    ))


# helper functions so i don't retype colors every time
def info(msg):    console.print(f"  [bold white][[*]][/bold white] {msg}")
def success(msg): console.print(f"  [bold green][[+]][/bold green] {msg}")
def warning(msg): console.print(f"  [bold yellow][[!]][/bold yellow] {msg}")
def error(msg):   console.print(f"  [bold red][[x]][/bold red] {msg}")

def section(title):
    console.print(f"\n[bold magenta]─────  {title}  ─────[/bold magenta]\n")


def make_table(title, columns):
    # columns = list of (name, style) tuples
    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        border_style="dim magenta",
        header_style="bold magenta",
        show_lines=False,
        expand=False
    )
    for col_name, col_style in columns:
        table.add_column(col_name, style=col_style)
    return table

def show_table(table):
    console.print(table)


def kv(label, value):
    # handles None/empty cleanly — whois/geo data is messy
    if value is None or value == "" or value == []:
        val = "[dim]N/A[/dim]"
    elif isinstance(value, list):
        val = ", ".join(str(v) for v in value)
    else:
        val = str(value)
    console.print(f"  [magenta]{label:<22}[/magenta] {val}")