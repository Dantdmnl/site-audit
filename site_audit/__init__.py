"""Scoped website exposure checks and public URL discovery."""

from .version import VERSION as __version__

__all__ = ["__version__", "main"]


def main() -> None:
    """Keep existing console entry points compatible without eager CLI imports."""
    from .cli import main as run
    run()
