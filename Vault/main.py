# main.py
# entry point for vault — run with: python main.py
# asks what you want to scan: local files or a github repo

import sys
from config import GITHUB_TOKEN
from utils.display import print_banner, error, warning, info, console, section
from modules import local_scanner, github_scanner


def ask_mode():
    console.print("\n  [bold yellow]What do you want to scan?[/bold yellow]\n")
    console.print("  [yellow]1.[/yellow] Local file or folder")
    console.print("  [yellow]2.[/yellow] Public GitHub repository")
    console.print("\n  [bold yellow]Your choice (1 or 2):[/bold yellow] ", end="")

    choice = input().strip()

    if choice == "1":
        return "local"
    elif choice == "2":
        return "github"
    else:
        warning("Invalid choice, defaulting to local scan.")
        return "local"


def ask_local_path():
    console.print("\n  [bold yellow]Enter file or folder path to scan:[/bold yellow] ", end="")
    path = input().strip().strip('"')  # strip quotes in case they drag-drop a path
    if not path:
        error("No path entered.")
        sys.exit(0)
    return path


def ask_github_url():
    console.print("\n  [bold yellow]Enter GitHub repo URL or owner/repo:[/bold yellow] ", end="")
    url = input().strip()
    if not url:
        error("No URL entered.")
        sys.exit(0)
    return url


def main():
    print_banner()

    while True:
        mode = ask_mode()

        if mode == "local":
            path = ask_local_path()
            local_scanner.run(path)

        elif mode == "github":
            url = ask_github_url()
            github_scanner.run(url, GITHUB_TOKEN)

        console.print("\n[bold yellow]─────  scan complete  ─────[/bold yellow]\n")

        console.print("  [bold yellow]Scan something else? (y/n):[/bold yellow] ", end="")
        again = input().strip().lower()
        if again != "y":
            console.print("\n  [dim]bye.[/dim]\n")
            break


if __name__ == "__main__":
    main()
