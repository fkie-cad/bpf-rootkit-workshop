# Exec 'a'

BPF application that hijacks `execve` invocations and attempts to modify
them to execute '/a' instead.
- preserves `envp`
- copies `filename` to `argv[0]`
- replaces `filename` with `/a`

## Usage
To those of you who feel adventurous, feel free to try it out on your
host. To all others, RUN IT INSIDE OF A VM.
```
clang -static a.c -o a
cp a /a
make execa
./execa
```
You can use the `-t <PID>` flag to limit hijacking to children of a
specific PID, e.g., your shell.
