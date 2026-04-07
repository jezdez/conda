# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Mock CLI implementation for `conda activate`.

A mock implementation of the activate shell command for better UX.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argparse import ArgumentParser, Namespace, _SubParsersAction


def configure_parser(sub_parsers: _SubParsersAction, **kwargs) -> ArgumentParser:
    p = sub_parsers.add_parser(
        "commands",
        help=(
            "List all available conda subcommands (including those from plugins). "
            "Generally only used by tab-completion."
        ),
        **kwargs,
    )
    p.set_defaults(func="conda.cli.main_commands.execute")

    return p


def execute(args: Namespace, parser: ArgumentParser) -> int:
    from ..base.context import context
    from .conda_argparse import BUILTIN_COMMANDS

    # Use BUILTIN_COMMANDS + registered plugin subcommands directly rather than
    # reading from parser.choices: _check_value creates a disconnected snapshot
    # of choices before _ensure_plugins_loaded() runs in __call__, so plugin
    # commands would be missing from find_builtin_commands(parser).
    print(
        *sorted({*BUILTIN_COMMANDS, *context.plugin_manager.get_subcommands()}),
        sep="\n",
        end="",
    )
    return 0
