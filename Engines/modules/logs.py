"""Legacy logging facade — delegates to ``opentide.core.logging``.

Engines call sites still import from here during TideKit migration. New code in
``src/opentide`` should import from ``opentide.core.logging`` directly.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from typing import List, Literal, NamedTuple

from opentide.core.logging import (
    LogCategory,
    coretide_intro,
    get_logger,
    is_debug_enabled,
    log,
    print_banner,
)

__all__ = [
    "ANSI",
    "Dialog",
    "DialogSection",
    "LogSegment",
    "LogCategory",
    "SegmentedLog",
    "coretide_intro",
    "get_logger",
    "is_debug_enabled",
    "log",
    "print_banner",
]


class ANSI:
    """ANSI escape helpers retained for Orchestration scripts."""

    @dataclass
    class Colors:
        PURPLE = "\033[95m"
        DARK_BLUE = "\033[34m"
        BLUE = "\033[94m"
        CYAN = "\033[96m"
        GREEN = "\033[92m"
        ORANGE = "\033[93m"
        RED = "\033[91m"

    @dataclass
    class Background:
        PURPLE = "\033[105m"
        DARK_BLUE = "\033[44m"
        BLUE = "\033[104m"
        CYAN = "\033[106m"
        GREEN = "\033[102m"
        ORANGE = "\033[103m"
        RED = "\033[101m"

    @dataclass
    class Formatting:
        BOLD = "\033[1m"
        UNDERLINE = "\033[4m"
        ITALICS = "\033[3m"
        STOP = "\033[0m"
        INVERSE = "\033[7m"

    class Inverse:
        def __init__(self, color_code: str) -> None:
            foreground_background_mapping = {
                ANSI.Colors.PURPLE: ANSI.Background.PURPLE,
                ANSI.Colors.DARK_BLUE: ANSI.Background.DARK_BLUE,
                ANSI.Colors.BLUE: ANSI.Background.BLUE,
                ANSI.Colors.CYAN: ANSI.Background.CYAN,
                ANSI.Colors.GREEN: ANSI.Background.GREEN,
                ANSI.Colors.ORANGE: ANSI.Background.ORANGE,
                ANSI.Colors.RED: ANSI.Background.RED,
            }
            background_foreground_mapping = {
                v: k for k, v in foreground_background_mapping.items()
            }
            if color_code in foreground_background_mapping:
                self.inverse = foreground_background_mapping[color_code]
            elif color_code in background_foreground_mapping:
                self.inverse = background_foreground_mapping[color_code]
            else:
                self.inverse = color_code

        def __str__(self) -> str:
            return self.inverse

    @staticmethod
    def stripper(string: object) -> str:
        ansi_escape = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
        return ansi_escape.sub("", str(string))

    @staticmethod
    def center(
        string: str,
        width: int,
        padding: str = " ",
        padding_color: str = "",
        padding_formatting: str | List[str] = "",
        edge_left: str = "",
        edge_right: str = "",
    ) -> str:
        STOP = ANSI.Formatting.STOP
        COLOR = padding_color
        FORMATTING = padding_formatting
        if isinstance(padding_formatting, list):
            FORMATTING = "".join(str(padding_formatting))

        diff_width = width - len(ANSI.stripper(string))
        remainder = diff_width % 2
        if remainder == 0:
            l_pad = r_pad = int(diff_width / 2)
        else:
            l_pad = int(diff_width / 2) + remainder
            r_pad = int(diff_width - l_pad)

        if edge_left:
            l_pad -= 1
        if edge_right:
            r_pad -= 1

        return (
            f"{COLOR}{FORMATTING}{padding * l_pad}{edge_left}{STOP}{string}"
            f"{COLOR}{FORMATTING}{edge_right}{padding * r_pad}{STOP}"
        )


class DialogSection(NamedTuple):
    section_name: str | None
    color: str
    message: str


class Dialog:
    """Legacy boxed dialog renderer — prefer ``log('FATAL', ...)`` for new code."""

    def __init__(self, border_color: str, sections: List[DialogSection]) -> None:
        dialog = ""
        BOLD = ANSI.Formatting.BOLD
        ITALICS = ANSI.Formatting.ITALICS
        STOP = ANSI.Formatting.STOP

        for index, section in enumerate(sections):
            section_name = "" if not section.section_name else section.section_name

            if index == 0:
                section_name = f"{STOP}{BOLD}{section.color}{section_name}{STOP}"
                edge = "─" * (len(ANSI.stripper(section_name)))
                section_name = ANSI.center(section_name, 78, "═", border_color, BOLD, "╡", "╞")
                upper_edge_line = border_color + "┌" + edge + "┐"
                upper_edge = f"{ANSI.center(upper_edge_line, 80)}{STOP}"
                bottom_edge_line = border_color + "└" + edge + "┘"
                bottom_edge = f"{BOLD}{border_color}║{ANSI.center(bottom_edge_line, 78)}{BOLD}{border_color}║"
                top_border = f"{BOLD}{border_color}╔{STOP}{section_name}{BOLD}{border_color}╗{STOP}"
                dialog += upper_edge + "\n" + top_border + "\n" + bottom_edge + "\n"
                for message in textwrap.wrap(section.message, 76):
                    line = (
                        f"{BOLD}{border_color}║{STOP}{ITALICS}{section.color} "
                        f"{message.center(76, ' ')} {STOP}{BOLD}{border_color}║{STOP}"
                    )
                    dialog += line + "\n"
            else:
                section_name = (
                    f"{STOP}{BOLD} {ANSI.Inverse(section.color)}{section_name}{STOP} {border_color}"
                )
                section_name = ANSI.center(
                    section_name, 78, "─", border_color, BOLD, edge_left="┤", edge_right="├"
                )
                top_border = f"{BOLD}{border_color}╟{STOP}{section_name}{BOLD}{border_color}╢{STOP}"
                dialog += top_border + "\n"
                for message in textwrap.wrap(section.message, 76):
                    line = (
                        f"{BOLD}{border_color}║{STOP}{section.color} {message.ljust(76, ' ')} "
                        f"{STOP}{BOLD}{border_color}║{STOP}"
                    )
                    dialog += line + "\n"

        dialog += f"{BOLD}{border_color}╚{'═' * 78}╝{STOP}"
        self.dialog = dialog

    def __str__(self) -> str:
        return self.dialog


class LogSegment(NamedTuple):
    message: str
    segment_color: str = ""
    segment_name: str = ""


class SegmentedLog:
    """Legacy segmented log layout — superseded by structlog key=value output."""

    def __init__(
        self,
        segments: List[LogSegment],
        accent: str,
        header: str,
        width: int,
        margin: int,
    ) -> None:
        STOP = ANSI.Formatting.STOP
        ITALICS = ANSI.Formatting.ITALICS
        log_data = ""
        segments = [s for s in segments if s.message]
        master_header = (
            f"{STOP}[{accent}{header}{STOP}]" + f"{accent}{'─' * (margin - (len(header) + 4))}{STOP}"
        )

        for segment in segments:
            if segment.segment_name:
                ansi_header = (
                    f"─┤{STOP}{segment.segment_color}{ITALICS} {segment.segment_name} "
                    f"{STOP}{accent}├{STOP} {segment.segment_color}"
                )
            else:
                ansi_header = f"{STOP} "

            if len(segments) == 1 and (
                len(segment.message) < (width - margin - len(ansi_header))
            ):
                cursor = "─"
            elif segment == segments[0]:
                cursor = "┬"
            elif (
                len(segment.message) < (60 - len(ANSI.stripper(ansi_header)))
                and segment == segments[-1]
                and len(segments) > 1
            ):
                cursor = "└"
            else:
                cursor = "├"

            ansi_header = f"{STOP}{accent}{cursor}{ansi_header}"
            header_text = ANSI.stripper(ansi_header)
            segment_message = header_text + str(segment.message)
            segment_messages = textwrap.wrap(segment_message, (width - margin))
            message_section = ""
            for line in segment_messages:
                if line == segment_messages[0]:
                    message_section += line + "\n"
                elif line == segment_messages[-1] and segment == segments[-1]:
                    message_section += f"{STOP}{accent}└{STOP}{segment.segment_color} {line}\n"
                else:
                    message_section += f"{STOP}{accent}├{STOP}{segment.segment_color} {line}\n"

            log_data += message_section.replace(header_text, ansi_header)
        log_data = master_header + f"\n{' ' * (margin - 2)}".join(log_data.split("\n"))
        self.log_data = log_data.rstrip().rstrip("\n")

    def __str__(self) -> str:
        return self.log_data


# Re-export category type for type checkers importing from Engines.
__category__ = Literal[
    "ONGOING",
    "SUCCESS",
    "WARNING",
    "INFO",
    "FAILURE",
    "FATAL",
    "DEBUG",
    "SKIP",
    "TITLE",
]
