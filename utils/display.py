# utils/display.py
# same as peek's display.py but themed for vault
# magenta felt right for peek, going with yellow/amber for vault — feels like a warning sign

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def print_banner():
    banner = """
 ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
 ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
 ██║   ██║███████║██║   ██║██║     ██║   
 ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
  ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   """

    console.print(Panel(
        Text(banner, style="bold yellow", justify="center"),
        subtitle="[dim italic]find what shouldn't have left the vault[/dim italic]",
        border_style="yellow",
        box=box.ROUNDED
    ))


def info(msg):    console.print(f"  [bold white][[*]][/bold white] {msg}")
def success(msg): console.print(f"  [bold green][[+]][/bold green] {msg}")
def warning(msg): console.print(f"  [bold yellow][[!]][/bold yellow] {msg}")
def error(msg):   console.print(f"  [bold red][[x]][/bold red] {msg}")
def found(msg):   console.print(f"  [bold red][[!]][/bold red] {msg}")  # for actual findings

def section(title):
    console.print(f"\n[bold yellow]─────  {title}  ─────[/bold yellow]\n")


def make_table(title, columns):
    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        border_style="dim yellow",
        header_style="bold yellow",
        show_lines=True,   # lines on for vault — easier to read findings
        expand=False
    )
    for col_name, col_style in columns:
        table.add_column(col_name, style=col_style, overflow="fold")  # fold long lines
    return table

def show_table(table):
    console.print(table)
