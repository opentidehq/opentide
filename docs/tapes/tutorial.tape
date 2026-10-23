# The tutorial path: scaffold, generate, validate (docs/usage/tutorial.md steps 1, 2 and 6).
#
# Render from the repository root, with opentide on PATH:
#   vhs docs/tapes/tutorial.tape
# docs/README.md says how to add or refresh a tape.

Output docs/assets/cli/tutorial.gif

Require opentide
Require python3

# Pinned so every render matches: shell, font, size, theme.
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set LineHeight 1.0
Set Width 1280
Set Height 560
Set Padding 24
Set Margin 24
Set MarginFill "#001489"
Set BorderRadius 10
Set Framerate 24
Set TypingSpeed 35ms
Set WaitTimeout 90s
Set WaitPattern /\$$/
Set Theme { "name": "opentide", "background": "#FFFFFF", "foreground": "#1B1F2A", "cursor": "#001489", "selection": "#C9D3F5", "black": "#1B1F2A", "red": "#B42318", "green": "#067647", "yellow": "#93370D", "blue": "#001489", "magenta": "#6F2DA8", "cyan": "#0B6E85", "white": "#D0D5DD", "brightBlack": "#667085", "brightRed": "#D92D20", "brightGreen": "#079455", "brightYellow": "#B54708", "brightBlue": "#2E4BC6", "brightMagenta": "#8E4EC6", "brightCyan": "#0E8AA6", "brightWhite": "#F2F4F7" }

# A person at a terminal, whatever runs the tape (CI, a coding agent).
Env OPENTIDE_OUTPUT "human"
Env COLORTERM "truecolor"

# A fresh HOME, so paths read ~/tutorial-detections on every machine.
Hide
Type "export PS1='$ ' TAPES=$PWD/docs/tapes HOME=$(mktemp -d) && cd && clear || exit 1"
Enter
Wait
Show

# Step 1.
Type `opentide setup --yes --name "Tutorial Detections" --org "Example Corp" --platform sentinel --path tutorial-detections`
Sleep 400ms
Enter
Wait+Screen /Created Tutorial Detections/
Wait
Sleep 3s

# Steps 3 to 5 write three YAML files; the tape writes them off camera.
Hide
Type "cd tutorial-detections && python3 $TAPES/tutorial_repo.py . && clear || exit 1"
Enter
Wait
Show

# Step 2.
Type "opentide generate"
Sleep 400ms
Enter
Wait+Screen /Generated \d+ files/
Wait
Sleep 2s

# Step 6.
Type "opentide validate"
Sleep 400ms
Enter
Wait+Screen /Validation passed/
Wait
Sleep 3s
Screenshot docs/assets/cli/tutorial.png
Sleep 100ms
