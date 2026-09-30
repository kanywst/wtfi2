# Records docs/demo.gif, the dashboard shown at the top of the README.
#
#   cargo build --release --features demo && vhs docs/demo.tape
#
# `--demo` replays scripted sweeps built from documentation addresses
# (RFC 5737) instead of probing, so the recording shows nothing about the
# network it was made on. Never record the real dashboard for the README.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1600
Set Height 560
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

Hide
Type "export PS1='$ ' PATH=$PWD/target/release:$PATH && alias wtfi='wtfi --demo' && clear"
Enter
Show

Type "wtfi -w"
Sleep 400ms
Enter
Sleep 15s
Type "q"
Sleep 500ms
