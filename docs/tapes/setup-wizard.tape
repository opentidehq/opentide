# The setup wizard: the branded welcome, the questions, the plan and the summary.
#
# Render from the repository root, with opentide on PATH:
#   vhs docs/tapes/setup-wizard.tape
# docs/README.md says how to add or refresh a tape.

Output docs/assets/cli/setup-wizard.gif

Require opentide

# Pinned so every render matches: shell, font, size, theme.
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set LineHeight 1.0
Set Width 1280
Set Height 760
Set Padding 24
Set Margin 24
Set MarginFill "#001489"
Set BorderRadius 10
Set Framerate 24
Set TypingSpeed 60ms
Set WaitTimeout 90s
Set WaitPattern /\$$/
Set Theme { "name": "opentide", "background": "#FFFFFF", "foreground": "#1B1F2A", "cursor": "#001489", "selection": "#C9D3F5", "black": "#1B1F2A", "red": "#B42318", "green": "#067647", "yellow": "#93370D", "blue": "#001489", "magenta": "#6F2DA8", "cyan": "#0B6E85", "white": "#D0D5DD", "brightBlack": "#667085", "brightRed": "#D92D20", "brightGreen": "#079455", "brightYellow": "#B54708", "brightBlue": "#2E4BC6", "brightMagenta": "#8E4EC6", "brightCyan": "#0E8AA6", "brightWhite": "#F2F4F7" }

# A person at a terminal, whatever runs the tape (CI, a coding agent).
Env OPENTIDE_OUTPUT "human"
Env COLORTERM "truecolor"

# A fresh HOME and an empty directory to set up.
Hide
Type "export PS1='$ ' HOME=$(mktemp -d) && cd && mkdir tutorial-detections && cd tutorial-detections && clear || exit 1"
Enter
Wait
Show

Type "opentide setup"
Sleep 400ms
Enter

# The welcome, then the repository name (the directory's, as offered).
Wait+Screen /Repository name/
Sleep 3s
Screenshot docs/assets/cli/setup-welcome.png
Enter

Wait+Screen /Organisation/
Type "Example Corp"
Sleep 400ms
Enter

Wait+Screen /Description/
Sleep 400ms
Enter

# Sentinel is the first platform.
Wait+Screen /Detection platforms/
Sleep 600ms
Space
Sleep 600ms
Enter

Wait+Screen /CI\/CD platform/
Sleep 800ms
Enter

Wait+Screen /Configure opentide MCP/
Sleep 600ms
Enter

Wait+Screen /Install agent skills/
Sleep 600ms
Enter

Wait+Line /Apply this setup plan/
Sleep 2s
Enter

Wait
Sleep 4s
Screenshot docs/assets/cli/setup-wizard.png

# The output has scrolled past what `Wait+Screen` reads, so check the files
# instead: the shell exits, and the tape fails, when no repository was written.
Hide
Type "test -f .opentide/configurations/platforms/sentinel.toml || exit 1"
Enter
Wait
