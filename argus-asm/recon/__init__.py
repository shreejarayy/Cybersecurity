"""
Argus ASM — recon package
Exports run_all() which executes every recon module concurrently
and returns a unified results dict.
"""

from .runner import run_all

__all__ = ["run_all"]
