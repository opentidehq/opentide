# A validation failure: the rule names an objective that does not exist
# (docs/usage/tutorial.md step 7).
#
# Render from the repository root, with opentide on PATH:
#   vhs docs/tapes/validate-failure.tape
# docs/README.md says how to add or refresh a tape.

Output docs/assets/cli/validate-failure.gif

Require opentide
Require python3

# Pinned so every render matches: shell, font, size, theme.
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set LineHeight 1.0
Set Width 1280
Set Height 340
Set Padding 24
Set Margin 24
Set MarginFill "#001489"
Set BorderRadius 10
Set Framerate 24
Set TypingSpeed 45ms
Set WaitTimeout 90s
Set WaitPattern /\$$/
Set Theme { "name": "opentide", "background": "#FFFFFF", "foreground": "#1B1F2A", "cursor": "#001489", "selection": "#C9D3F5", "black": "#1B1F2A", "red": "#B42318", "green": "#067647", "yellow": "#93370D", "blue": "#001489", "magenta": "#6F2DA8", "cyan": "#0B6E85", "white": "#D0D5DD", "brightBlack": "#667085", "brightRed": "#D92D20", "brightGreen": "#079455", "brightYellow": "#B54708", "brightBlue": "#2E4BC6", "brightMagenta": "#8E4EC6", "brightCyan": "#0E8AA6", "brightWhite": "#F2F4F7" }

# A person at a terminal, whatever runs the tape (CI, a coding agent).
Env OPENTIDE_OUTPUT "human"
Env COLORTERM "truecolor"

# validate prints absolute paths, so HOME is a fixed directory and the
# still reads the same on every machine.
Hide
Type "export PS1='$ ' TAPES=$PWD/docs/tapes HOME=/tmp/opentide-tape && rm -rf $HOME && mkdir $HOME && cd && python3 $TAPES/tutorial_repo.py tutorial-detections --setup --generate --state dangling-reference && cd tutorial-detections && clear || exit 1"
Enter
Wait
Show

# Whatever validate prints for this repository; it names the unknown UUID
# whichever renderer prints it.
Type "opentide validate"
Sleep 400ms
Enter
Wait+Screen /DEADBEEF0000/
Wait
Sleep 3s
Screenshot docs/assets/cli/validate-failure.png
Sleep 100ms
