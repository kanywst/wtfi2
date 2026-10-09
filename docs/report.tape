# Records docs/report.png for the README's "See it" section.
#
#   cargo build --release --features demo && vhs docs/report.tape
#
# Scripted with --demo on documentation addresses (RFC 5737); see
# docs/demo.tape for why the README is never recorded from a real network.

Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 760
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

Hide
Type "export PS1='$ ' PATH=$PWD/target/release:$PATH && alias wtfi='wtfi --demo' && clear"
Enter
Show

Type "wtfi -v"
Sleep 400ms
Enter
Sleep 4s
Screenshot docs/report.png
