import subprocess, sys, os

cwd = r'C:\Workspace\Codex_tools'
os.chdir(cwd)


def run(args, check=True):
    print(f'$ {" ".join(args)}')
    r = subprocess.run(args, capture_output=True, text=True, encoding='utf-8')
    if r.stdout:
        print(r.stdout)
    if r.stderr:
        print('STDERR:', r.stderr, file=sys.stderr)
    if check and r.returncode != 0:
        sys.exit(r.returncode)
    return r


run(['git', 'init', '-b', 'main'])
run(['git', 'add', '.'])

msg = 'chore: scaffold engineering skills config\n\n'
msg += '- AGENTS.md: top-level Agent skills block\n'
msg += '- docs/agents/issue-tracker.md: GitHub + gh CLI, PRs not a triage surface\n'
msg += '- docs/agents/triage-labels.md: default five-role vocabulary\n'
msg += '- docs/agents/domain.md: single-context layout'

run(['git', 'commit', '-m', msg])
run(['git', 'remote', 'add', 'origin', 'https://github.com/Shanqianlvshui/Codex_tools.git'])

print('--- git status ---')
run(['git', 'status'])
print('--- git log ---')
run(['git', 'log', '--oneline'])