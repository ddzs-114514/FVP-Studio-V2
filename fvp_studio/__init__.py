"""FVP Studio V2 core package.

The package is intentionally independent from the RFVP runtime.  It reads and
writes HCB files while preserving unknown bytes, so the editor can be used as a
safe analysis tool before game-specific profiles are added.
"""

__version__ = "0.2.0"
