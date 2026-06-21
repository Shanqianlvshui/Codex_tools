import subprocess, sys, os

cwd = r'C:\Workspace\Codex_tools'
os.chdir(cwd)


def run(args):
    print(f'$ {" ".join(args)}')
    r = subprocess.run(args, capture_output=True, text=True, encoding='utf-8')
    if r.stdout:
        print(r.stdout)
    if r.stderr:
        print('STDERR:', r.stderr, file=sys.stderr)
    if r.returncode != 0:
        sys.exit(r.returncode)
    return r


run(['git', 'add', '-A'])
run(['git', 'commit', '-m', 'chore: remove throwaway git init script'])
run(['git', 'push', 'origin', 'main'])
print('--- git status ---')
run(['git', 'status'])
print('--- git log ---')
run(['git', 'log', '--oneline', '--decorate', '--all'])