#!/usr/bin/env python3
"""PreToolUse guard of the syntexia-agents fleet (v4). Defense in depth.

The strongest barriers live outside this file: a disposable clone with no remote
and no push credentials (scripts/prepare_sweep_clone.sh), a session environment
that neutralizes git global config and SSH (settings.json "env"),
permissions.deny, and the two human gates. This hook adds a parser that
understands wrappers, nested shells, heredocs, command substitution, inline
interpreter code and shell scripts on disk.

Blocked
  Bash  : git outside a read/commit allowlist (push, every remote or config
          write, history rewriting, discarding work), every GitHub/GitLab CLI
          call, privilege escalation, network tools, live-system and cloud CLIs,
          package installs, process killing, destructive file operations outside
          /tmp, writes into .claude/ or .git/ or outside the project and /tmp,
          reads of secret files, dumps of the environment or of secret variables,
          content-mode greps for secret literals.
  Read  : secret files (.env, private keys, credential stores, /proc/*/environ).
  Grep  : searches inside secret files, content-mode searches for secret
          literals (use files_with_matches / count, or
          .claude/scripts/redacted_secret_scan.py).
  Edit, Write, NotebookEdit : .claude/, .git/, secret files, anything outside
          the project and /tmp.

Not visible to this parser: a renamed copy of a binary, code that an allowed
program loads by itself (a test suite, a build tool target not named like a
release). See PLAYBOOK.md section 8.

Fails CLOSED: unreadable input, unparsable command, nesting too deep or any
internal error exits 2. Claude Code treats exit 1 as non-blocking, so every
exception path is converted to 2 at the bottom of this file.
"""
import codecs
import fnmatch
import json
import os
import re
import shlex
import sys

MAX_DEPTH = 6
MAX_SCRIPT_BYTES = 1_000_000
MAX_COMMAND_CHARS = 100_000  # shlex is quadratic; a hook that times out fails open
MAX_EXPANSIONS = 2000
GLOB_BUDGET = 20000  # directory entries visited per command; beyond: refuse, never hang
DEFAULT_SCRATCH = "/tmp/sweep"
HOOK_CANARY = "FLEET_HOOK_CANARY"

PREFIX = "Bloque par la flotte syntexia-agents : "
HINT = (" Les actions sur le depot distant, les systemes vivants et les secrets sont "
        "humaines. Laisse l'etat local tel quel et rends la main.")


class Blocked(Exception):
    """Raised with a human-readable reason when a call must be refused."""


# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #

SEPARATORS = {";", "&&", "||", "|", "&", "|&", ";;", ";&", ";;&", "(", ")", "()",
              "\n", "{", "}"}
REDIRECTS = {">", ">>", "<", "<>", ">|", ">&", "<&", "&>", "&>>"}
HEREDOC_OPS = {"<<", "<<-"}
HERESTRING_OPS = {"<<<"}
LEADING_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until",
                    "esac", "!", "time", "coproc", "in"}
SKIP_SEGMENT_KEYWORDS = {"for", "select", "case", "function"}

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "ash",
          "rbash"}
INTERPRETERS = {"python", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua",
                "pwsh", "powershell", "osascript", "tclsh", "rscript", "julia"}
AWKS = {"awk", "gawk", "mawk", "nawk"}
EDITORS = {"vi", "vim", "nvim", "ex", "ed", "emacs", "emacsclient"}

# Programs that execute a command given on their own command line, with the
# options that consume a value and the number of positional arguments that
# precede the command (duration, priority, mask, lock file).
WRAPPERS = {
    "env": ({"-u", "--unset", "-C", "--chdir", "-P"}, 0),
    "command": (set(), 0), "builtin": (set(), 0), "noglob": (set(), 0),
    "exec": ({"-a"}, 0), "nohup": (set(), 0),
    "time": ({"-f", "--format", "-o", "--output"}, 0),
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, 1),
    "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid",
                "-u", "--uid"}, 0),
    "stdbuf": ({"-i", "-o", "-e", "--input", "--output", "--error"}, 0),
    "chrt": (set(), 1), "taskset": ({"-c", "--cpu-list"}, 1),
    "setsid": (set(), 0),
    "flock": ({"-E", "--conflict-exit-code", "-w", "--timeout", "--wait"}, 1),
    "watch": ({"-n", "--interval", "-q", "--equexit"}, 0),
    "unbuffer": (set(), 0),
    "strace": ({"-o", "-e", "-p", "-s", "-u", "-E", "-a", "-I", "-b", "-P", "-S", "-X",
                "-O"}, 0),
    "ltrace": ({"-o", "-e", "-p", "-s", "-u", "-a", "-n", "-l", "-x"}, 0),
    "valgrind": (set(), 0), "caffeinate": ({"-t", "-w"}, 0),
    "busybox": (set(), 0),
    "unshare": ({"-S", "--setuid", "-G", "--setgid", "-R", "--root", "-w", "--wd"}, 0),
    "firejail": (set(), 0), "bwrap": (set(), 0), "catchsegv": (set(), 0),
    "xvfb-run": ({"-n", "-s", "-f", "-e", "-p", "-w", "--server-num", "--server-args",
                  "--auth-file", "--error-file", "--xauth-protocol", "--wait"}, 0),
    "dbus-run-session": (set(), 0), "eatmydata": (set(), 0), "chronic": (set(), 0),
    "nocache": (set(), 0), "trickle": ({"-d", "-u", "-w", "-t", "-l"}, 0),
    "proxychains": ({"-f"}, 0), "proxychains4": ({"-f"}, 0),
    "torsocks": ({"-u", "-p", "-a", "-P"}, 0),
    "xargs": ({"-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "-L", "-n",
               "--max-args", "-P", "--max-procs", "-s", "--max-chars",
               "--process-slot-var"}, 0),
    "parallel": ({"-j", "--jobs", "--tmpdir", "--joblog", "--results", "-a",
                  "--arg-file", "--delay", "--timeout", "--retries"}, 0),
    "sem": ({"-j", "--jobs", "--id"}, 0),
    "script": (set(), 0),
}
INPUT_FED_WRAPPERS = {"xargs", "parallel", "sem"}

PRIVILEGE = {"sudo", "doas", "su", "pkexec", "runuser", "run0", "chroot", "nsenter",
             "setpriv", "capsh", "machinectl"}
GIT_HOSTING_CLIS = {"gh", "hub", "glab", "gitlab", "tea", "bitbucket"}
NETWORK = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "scp", "sftp",
           "rsync", "ftp", "tftp", "lftp", "nslookup", "dig", "host", "drill", "ping",
           "ping6", "traceroute", "tracepath", "mtr", "whois", "aria2c", "http", "https",
           "xh", "httpie", "websocat", "grpcurl", "wscat", "nmap", "masscan"}
LIVE_SYSTEMS = {
    "aws", "gcloud", "gsutil", "bq", "az", "kubectl", "k9s", "helm", "terraform", "tofu",
    "pulumi", "ansible", "ansible-playbook", "doctl", "hcloud", "linode-cli", "s3cmd",
    "rclone", "mc", "eksctl", "systemd-run",
    "docker", "docker-compose", "podman", "nerdctl", "ctr", "crictl",
    "systemctl", "service", "journalctl", "loginctl", "crontab", "at", "batch", "tmux",
    "screen", "kill", "pkill", "killall", "reboot", "shutdown", "halt", "poweroff",
    "init", "telinit",
    "psql", "pg_dump", "pg_dumpall", "pg_restore", "mysql", "mysqldump", "mariadb",
    "mongo", "mongosh", "mongodump", "mongorestore", "redis-cli", "sqlcmd", "supabase",
    "sqlite3",
    "vercel", "netlify", "fly", "flyctl", "heroku", "railway", "firebase", "wrangler",
    "twilio", "stripe", "serverless", "sls", "eb", "copilot",
    "vault", "op", "bw", "pass", "gpg", "gpg2", "age", "sops", "secret-tool", "keyctl",
    "security", "direnv", "dotenv", "env-cmd",
}
DESTRUCTIVE = {"dd", "shred", "wipefs", "fdisk", "sfdisk", "parted", "truncate", "srm",
               "mkswap", "blkdiscard", "ln", "link", "mknod", "mkfifo"}
# Names checked anywhere inside a wrapper's arguments (unambiguous program names,
# never ordinary words), in case the option parsing above guessed wrong.
STRICT_ANYWHERE = (PRIVILEGE | GIT_HOSTING_CLIS | DESTRUCTIVE |
                   {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "scp",
                    "sftp", "rsync", "lftp", "websocat", "nmap", "aws", "gcloud", "gsutil",
                    "az", "kubectl", "helm", "terraform", "tofu", "pulumi", "docker",
                    "podman", "systemctl", "journalctl", "crontab", "tmux", "screen",
                    "pkill", "killall", "psql", "mysql", "mongosh", "redis-cli",
                    "supabase", "vercel", "netlify", "flyctl", "heroku", "wrangler",
                    "vault", "sops", "gpg", "direnv", "npx", "pnpx", "bunx", "pipx",
                    "git", "rm"} | SHELLS | INTERPRETERS)

PACKAGE_MANAGERS_ALWAYS = {"npx", "pnpx", "bunx", "pipx", "corepack", "apt", "apt-get",
                           "aptitude", "yum", "dnf", "apk", "zypper", "pacman", "snap",
                           "flatpak", "brew", "port", "choco", "winget", "conda", "mamba",
                           "micromamba"}
PACKAGE_VERBS = {"install", "i", "in", "add", "ci", "update", "upgrade", "up", "remove",
                 "rm", "uninstall", "un", "unlink", "publish", "unpublish", "link", "exec",
                 "dlx", "create", "download", "sync", "x", "global", "self", "get",
                 "require", "push", "yank", "login", "adduser", "token", "deprecate",
                 "dist-tag", "owner", "access"}
PACKAGE_MANAGERS_VERBS = {"pip", "uv", "poetry", "pdm", "npm", "pnpm", "yarn", "bun",
                          "gem", "bundle", "bundler", "cargo", "go", "composer", "nuget",
                          "dotnet", "mvn", "gradle", "hatch", "rye", "pipenv"}
RELEASE_RE = re.compile(r"(deploy|release|publish|push|upload|prod|ship|migrat|rollout)",
                        re.I)

WRITE_ALL_ARGS = {"tee", "rm", "rmdir", "chmod", "chown", "chgrp", "touch", "mkdir",
                  "unlink"}
WRITE_LAST_ARG = {"cp", "mv", "install", "rsync"}
SAFE_WRITE_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "-"}

GIT_READ_ONLY = {
    "status", "log", "show", "diff", "ls-files", "ls-tree", "blame", "annotate", "grep",
    "rev-parse", "rev-list", "cat-file", "describe", "shortlog", "merge-base",
    "name-rev", "for-each-ref", "show-ref", "count-objects", "var", "version", "help",
    "check-ignore", "check-attr", "diff-tree", "diff-files", "diff-index",
    "whatchanged", "range-diff", "verify-commit", "verify-tag", "show-branch", "cherry",
}
GIT_ALLOWED = GIT_READ_ONLY | {
    "fsck", "format-patch", "archive", "reflog", "worktree", "branch", "tag", "stash",
    "remote", "add", "commit", "switch", "checkout", "revert", "cherry-pick", "mv", "rm",
    "restore", "reset", "notes",
}
GIT_OPTS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                       "--super-prefix", "--config-env", "--exec-path", "--list-cmds",
                       "--attr-source"}
GIT_DANGEROUS_CONFIG = ("alias.", "core.", "credential", "url.", "remote.", "filter.",
                        "diff.", "merge.", "protocol.", "http.", "include", "gpg.",
                        "uploadpack.", "receive.", "submodule.", "sequence.", "pager.",
                        "interactive.", "safe.", "transfer.", "fetch.", "push.", "ssh.",
                        "sendemail.")

SECRET_LITERAL_RE = re.compile(
    r"sk-ant|sk-proj|sk_live|rk_live|AKIA|ASIA[0-9A-Z]{4}|PRIVATE KEY|BEGIN[ A-Z]*PRIVATE"
    r"|xox[abprs]-|xox\[|gh[pousr]_|gh\[|github_pat_|glpat-|eyJ|\bre_(\[|[A-Za-z0-9]{8,})"
    r"|AIza|service_role|SG\.[A-Za-z0-9_-]{10}|KEY0[0-9A-Fa-f]")
SECRET_NAME = (r"[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASS|PASSWD|PASSWORD|CRED|CREDENTIAL|"
               r"PRIVATE|DSN|DATABASE_URL|AUTH|COOKIE|SESSION)[A-Za-z0-9_]*")
SECRET_VAR_RE = re.compile(r"\$\{?(" + SECRET_NAME + r")\}?", re.I)
SECRET_NAME_RE = re.compile(r"^" + SECRET_NAME + r"$", re.I)
# Environment variables that change what an allowed program executes, where it
# connects or which config it loads. Setting them is refused in any form
# (VAR=x cmd, VAR=x alone, export, declare -x, env VAR=x).
DANGEROUS_ENV_RE = re.compile(
    r"^(GIT_\w+|SSH_\w+|PAGER|EDITOR|VISUAL|LESSOPEN|LESSCLOSE|LD_\w+|DYLD_\w+|BASH_ENV"
    r"|ENV|PROMPT_COMMAND|PS[0-4]|SHELLOPTS|BASHOPTS|CDPATH|PATH|HOME|PERL5OPT|PERL5LIB"
    r"|PERLLIB|RUBYOPT|RUBYLIB|PYTHONSTARTUP|PYTHONHOME|PYTHONINSPECT"
    r"|PYTHONUSERBASE|NODE_OPTIONS|NODE_PATH|(HTTPS?|ALL|FTP|NO|SOCKS)_PROXY"
    r"|(https?|all|ftp|no|socks)_proxy|SSL_CERT_\w+|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE"
    r"|PIP_\w+|NPM_CONFIG_\w+|npm_config_\w+|UV_\w+|SEMGREP_\w+|TRIVY_\w+|GH_\w+"
    r"|GITHUB_\w+|CLAUDE_\w+|ANTHROPIC_\w+|XDG_CONFIG_HOME|FLEET_\w+|GEM_PATH|GEM_HOME"
    r"|LUA_PATH|LUA_CPATH|CLASSPATH|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS"
    r"|MAVEN_OPTS|GRADLE_OPTS|DOTNET_\w+|RUSTC_WRAPPER|RUSTC|CARGO_\w+|GOFLAGS|GOPROXY"
    r"|GONOSUMDB|GOPRIVATE|BASH_FUNC_\S+|PYTHONSAFEPATH|PYTHONNOUSERSITE)$")
SAFE_ENV_VALUES = {("GIT_PAGER", "cat"), ("GIT_PAGER", ""), ("PAGER", "cat"), ("PAGER", ""),
                   ("GIT_TERMINAL_PROMPT", "0"), ("GIT_EDITOR", "true"), ("GIT_EDITOR", ":"),
                   ("EDITOR", "true"), ("GIT_SEQUENCE_EDITOR", "true")}
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema",
                     ".tpl")
PRIVATE_KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
SECRET_BASENAMES = {".git-credentials", ".netrc", "_netrc", ".pgpass", ".my.cnf",
                    ".npmrc", ".pypirc", ".dockercfg", ".envrc", "credentials.json",
                    "service-account.json", "secrets.json", "secrets.yaml",
                    "secrets.yml", ".htpasswd", "shadow", "gshadow"}
SECRET_EXTENSIONS = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk",
                     ".kdbx", ".gpg", ".age")

INLINE_CODE_DANGER_RE = re.compile(r"""(?ix)
    \bgit\b[\s'",\[\]]{1,6}(push|send-pack|http-push|config|remote|credential|clone
        |fetch|ls-remote|subtree|update-ref|filter-branch|filter-repo|reset|clean
        |rebase|pull|merge)\b
  | \b(gh|hub|glab)\b[\s'",\[\]]{1,6}(api|pr|repo|release|secret|workflow|auth|gist)\b
  | \b(urllib|urllib2|urllib3|http\.client|httplib|requests|httpx|aiohttp|socket
        |smtplib|ftplib|telnetlib|paramiko|pycurl|websocket|websockets|grpc|boto3
        |botocore)\b
  | \b(subprocess|os\.system|os\.popen|os\.exec\w*|os\.spawn\w*|pty\.spawn
        |commands\.getoutput|create_subprocess_\w+)\b
  | child_process|\bexecSync\b|\bspawnSync\b|\bfetch\s*\(|\bXMLHttpRequest\b
  | require\(\s*['"](https?|net|dgram|tls|dns|child_process)['"]\s*\)
  | \bprocess\.env\b|\bos\.environ\b|\bgetenv\s*\(|\bENV\[
  | \beval\s*\(|\bexec\s*\(|\b__import__\b|\bb64decode\b|\bcompile\s*\(
  | \bmarshal\.loads|\bpickle\.loads|\bimportlib\b
  | \bsystem\s*\(|\bIO::Socket\b|\bNet::|\bLWP\b|\bopen3\b|\bqx\b|`
  | \b(passthru|shell_exec|proc_open|popen|pcntl_exec|fsockopen|pfsockopen
        |stream_socket_client|curl_init|curl_exec|curl_multi_exec)\b
  | \b(file_get_contents|fopen|readfile|copy)\s*\(\s*['"]?(https?|ftp|php|data)://
  | os\.execute|io\.popen|\bsystem2\s*\(|\bpipe\s*\(|download\.file|\burl\s*\(
  | IO\.popen|Open3|%x\{|\bspawn\s*\(|Kernel\.(system|exec)|\bfork\b|\bexec\s
  | \bopen\s*\([^)]*['"]\s*[|]|\bopen\s*\([^)]*,\s*['"][^'"]*[wax+][^'"]*['"]
  | \.write_(text|bytes)\s*\(|\b(shutil\.(rmtree|move|copy\w*)|os\.(remove|unlink
        |rmdir|removedirs|rename|replace|chmod|truncate|symlink|link))\b
  | \bctypes\b|\bprocess\.binding\b|\bvm\.run\w*
  | \bDeno\.(run|Command|connect|connectTls|listen|readTextFile|readFile|writeTextFile
        |writeFile|remove|env|openKv)\b|\bBun\.(spawn|spawnSync|\$|file|write|env)\b
  | /dev/(tcp|udp)/|/proc/[^\s'"]*/environ
  | \.claude/|\.git/
  | (?<![\w.])\.env(rc)?(?!\.(example|sample|template|dist|defaults|schema|tpl))\b
  | \bid_(rsa|dsa|ecdsa|ed25519)\b|\.ssh/|\.aws/|\.git-credentials|\.netrc
""")
SCRIPT_FILE_DANGER_RE = re.compile(r"""(?ix)
    \bgit\b[\s'",\[\]]{1,6}(push|send-pack|http-push|credential|subtree|update-ref
        |filter-branch|filter-repo)\b
  | \bgit\b[\s'",\[\]]{1,6}(config|remote)\b[^\n]{0,80}\b(alias|url|pushurl|insteadof
        |credential|hookspath|sshcommand|set-url|add)\b
  | \b(gh|hub|glab)\b[\s'",\[\]]{1,6}(api|pr|repo|release|secret|workflow)\b
  | /dev/(tcp|udp)/
""")
DATA_HEREDOC_DANGER_RE = re.compile(
    r"\bgit\b[^\n]{0,40}\b(push|send-pack|http-push)\b|\b(gh|hub|glab)\s+(api|pr|repo)\b"
    r"|/dev/(tcp|udp)/")
AWK_DANGER_RE = re.compile(
    r"\bsystem\s*\(|\|\s*getline|getline[^;{}]*<|\|&|\b(print|printf)\b[^;{}]*[|>]"
    r"|\bclose\s*\(|\bfflush\s*\(|/inet/")
SED_S_RE = re.compile(
    r"(?:^|[;\n{}\s!0-9$/])s([^\\\n])((?:\\.|(?!\1).)*)\1((?:\\.|(?!\1).)*)\1([^;\n}]*)")
SED_CMD_RE = re.compile(
    r"(?:^|[;\n{}])\s*(?:(?:\d+|\$|/(?:\\.|[^/\\])*/)\s*(?:,\s*(?:\d+|\$|/(?:\\.|[^/\\])*/"
    r"|[+~]\d+))?)?\s*!?\s*([eEwWrRF])(?![A-Za-z])\s*([^;\n}]*)")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def exe_name(tok):
    base = tok.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def family(name):
    m = re.match(r"^(python|pip|node|perl|ruby|php|lua)[\d.]*$", name)
    return m.group(1) if m else name


def is_assignment(tok):
    return re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=", tok) is not None


def path_candidates(tok):
    """A token and its sub-parts that may be paths (--opt=path, rev:path, a,b).
    Parts containing whitespace are prose (a commit message), not paths."""
    parts = {tok}
    for sep in ("=", ":", ","):
        for p in list(parts):
            parts.update(x for x in p.split(sep) if x)
    return {p for p in parts if not any(ch.isspace() for ch in p)}


def is_secret_path(tok):
    for cand in path_candidates(tok):
        c = cand.strip("'\"").replace("\\", "/")
        if not c:
            continue
        low = c.lower()
        if re.search(r"/proc/[^/\s]*/environ", low) or low.startswith("/proc/self/environ"):
            return True
        if "/.ssh/" in low or low.startswith((".ssh/", "~/.ssh")) or low in (".ssh", "~/.ssh"):
            return True
        if "/.aws/" in low or low.startswith((".aws/", "~/.aws")):
            return True
        if "/.config/gh/" in low or "/.docker/config.json" in low or "/.kube/config" in low:
            return True
        base = low.rstrip("/").rsplit("/", 1)[-1]
        if base.startswith(".env") and not base.endswith(SAFE_ENV_SUFFIXES):
            return True
        if base.endswith(".env") and len(base) > 4 and \
                not base.startswith(("example", "sample", "template")):
            return True
        if base in SECRET_BASENAMES:
            return True
        if base.startswith(PRIVATE_KEY_NAMES) and not base.endswith(".pub"):
            return True
        if base.endswith(SECRET_EXTENSIONS):
            return True
    return False


def decode_ansi_c(text):
    """Replace bash $'...' strings by an equivalent single-quoted literal so that the
    parser sees what bash will execute ($'\x2eenv' is .env)."""
    if "$'" not in text:
        return text
    out, i, n = [], 0, len(text)
    in_single = in_double = False
    while i < n:
        c = text[i]
        if in_single:
            out.append(c)
            in_single = c != "'"
            i += 1
            continue
        if c == "\\":
            out.append(text[i:i + 2])
            i += 2
            continue
        if c == '"':
            in_double = not in_double
        elif c == "'" and not in_double:
            in_single = True
        elif c == "$" and not in_double and text[i + 1:i + 2] == "'":
            j = i + 2
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise Blocked("chaine $'...' non fermee, blocage par defaut.")
            try:
                raw = text[i + 2:j].encode("latin-1", "backslashreplace")
                decoded = codecs.decode(raw, "unicode_escape")
            except Exception:
                raise Blocked("chaine $'...' non decodable, blocage par defaut.")
            out.append("'" + decoded.replace("'", "'\\''") + "'")
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def expand_braces(word, limit=64):
    """Bash comma brace expansion ({a,b}), bounded. Sequences {1..3} stay literal."""
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not m:
        return [word]
    results = []
    for part in m.group(1).split(","):
        for w in expand_braces(word[:m.start()] + part + word[m.end():], limit):
            results.append(w)
            if len(results) >= limit:
                return results
    return results


def glob_matches(pattern, ctx):
    """Bash-like expansion of a glob (no dotfiles unless the component starts with a
    dot), walked level by level with a budget of directory entries shared by the
    whole command. Exceeding the budget refuses the command: a hook that times out
    fails open."""
    if not re.search(r"[*?\[]", pattern):
        return []
    pattern = os.path.expanduser(pattern)
    if pattern.startswith("/"):
        current, parts = ["/"], pattern.split("/")[1:]
    else:
        current, parts = [ctx.cwd], pattern.split("/")
    for part in parts:
        if part in ("", "."):
            continue
        nxt = []
        if not re.search(r"[*?\[]", part):
            nxt = [os.path.join(c, part) for c in current if os.path.lexists(os.path.join(c, part))]
        else:
            for c in current:
                try:
                    it = os.scandir(c)
                except OSError:
                    continue
                with it:
                    for entry in it:
                        ctx.glob_budget -= 1
                        if ctx.glob_budget < 0:
                            raise Blocked("motif glob trop large pour etre controle "
                                          "(%s), blocage par defaut." % pattern[:60])
                        if entry.name.startswith(".") and not part.startswith("."):
                            continue
                        if fnmatch.fnmatchcase(entry.name, part):
                            nxt.append(os.path.join(c, entry.name))
        current = nxt[:MAX_EXPANSIONS]
        if not current:
            return []
    return current


def word_variants(word, ctx):
    """The word, its brace expansions and what its globs match on disk."""
    out = []
    for w in expand_braces(word):
        out.append(w)
        out.extend(glob_matches(w, ctx))
    return out


def check_env_name(name, command_name=None, value=None, ctx=None):
    if name == "IFS" and command_name in ("read", "mapfile", "readarray"):
        return
    if value is not None and (name, value) in SAFE_ENV_VALUES:
        return
    if name == "PYTHONPATH":
        if not value:
            return
        entries = [e for e in value.split(":") if e]
        if ctx is not None and ctx.project and entries and all(
                not e.startswith(("$", "~")) and under(ctx.resolve(e), ctx.project)
                and not any(under(ctx.resolve(e), r) for r in ctx.scratch_roots)
                for e in entries):
            return
        raise Blocked("PYTHONPATH hors du projet : un sitecustomize.py y serait execute par "
                      "tout programme Python.")
    if name == "IFS" or DANGEROUS_ENV_RE.match(name):
        raise Blocked("modification de la variable d'environnement %s : elle change ce que "
                      "les programmes executent ou chargent." % name)


VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def substitute_vars(word, ctx):
    if "${!" in word:
        raise Blocked("expansion indirecte de variable (${!...}).")

    def rep_(m):
        name = m.group(1) or m.group(2)
        return ctx.vars.get(name, m.group(0))
    return VAR_REF_RE.sub(rep_, word)


def under(path, root):
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


class Context:
    def __init__(self, cwd, project):
        self.cwd = cwd or os.getcwd()
        self.project = os.path.realpath(project) if project else None
        self.vars = {}
        self.glob_budget = GLOB_BUDGET
        roots = [DEFAULT_SCRATCH]
        if os.environ.get("FLEET_SCRATCH_DIR"):
            roots.append(os.environ["FLEET_SCRATCH_DIR"])
        # A scratch root that is itself a symbolic link is ignored (fail closed): a link
        # planted at /tmp/sweep would turn its target, "/" for instance, into a
        # writable area. Writes there are then refused like any path outside the project.
        self.scratch_roots = [os.path.realpath(r) for r in roots if not os.path.islink(r)]

    def resolve(self, p):
        p = os.path.expanduser(p.strip("'\""))
        if not os.path.isabs(p):
            p = os.path.join(self.cwd, p)
        return os.path.realpath(p)

    def in_scratch(self, p):
        """Under the sweep scratch area and not inside the project itself (a
        disposable clone may live under /tmp)."""
        rp = self.resolve(p)
        if self.project is not None and under(rp, self.project):
            return False
        return any(under(rp, r) for r in self.scratch_roots)

    def contained(self, rp):
        if any(under(rp, r) for r in self.scratch_roots):
            return True
        return self.project is None or under(rp, self.project)

    def writable(self, p):
        """Raise unless an agent may write p: inside the project (never .claude/ or
        .git/) or under the sweep scratch area (/tmp/sweep). Braces and globs are
        expanded the way bash would before the check."""
        variants = word_variants(p, self)
        if len(variants) > 1 or variants[0] != p:
            for v in variants:
                self._writable_one(v)
            return
        self._writable_one(p)

    def protected(self, p):
        """Raise when p (a source or a destination) resolves inside .claude/ or .git/."""
        for v in word_variants(p, self):
            raw = v.strip("'\"")
            if raw.startswith("$") or "$(" in raw:
                continue
            parts = self.resolve(raw).replace("\\", "/").split("/")
            if ".claude" in parts or ".git" in parts:
                raise Blocked("operation sur .claude/ ou .git/ (%s)." % raw[:80])

    def _writable_one(self, p):
        raw = p.strip("'\"")
        if raw in SAFE_WRITE_TARGETS or raw.startswith("/dev/fd/"):
            return
        if raw.startswith("$") or "$(" in raw or "`" in raw or raw.startswith("~"):
            if raw.startswith("~"):
                raise Blocked("ecriture dans le repertoire personnel (%s)." % raw[:60])
            raise Blocked("cible d'ecriture non resolue (%s) : utilise un chemin "
                          "litteral." % raw[:60])
        rp = self.resolve(raw)
        parts = rp.replace("\\", "/").split("/")
        if ".claude" in parts or ".git" in parts:
            raise Blocked("ecriture dans .claude/ ou .git/ (%s) : la configuration de la "
                          "flotte et les internes git ne se modifient pas pendant une "
                          "passe." % raw[:80])
        if not self.contained(rp):
            raise Blocked("ecriture hors du projet et de /tmp/sweep (%s)." % raw[:80])


# --------------------------------------------------------------------------- #
# Command-line analysis
# --------------------------------------------------------------------------- #

def lex(text):
    lx = shlex.shlex(text, posix=True, punctuation_chars="();<>|&\n")
    lx.whitespace = " \t\r"
    lx.whitespace_split = True
    lx.commenters = ""  # a '#' must never hide the rest of a line from the parser
    try:
        return list(lx)
    except ValueError as e:
        raise Blocked("commande non analysable (%s), blocage par defaut." % e)


def split_heredocs(text):
    """Remove heredoc bodies. Returns (text_without_bodies, [bodies in order]).
    Operators are taken only from lines that tokenize on their own, so a '<<'
    inside a quoted string is not mistaken for a heredoc; a mismatch with the
    full parse is caught by the caller."""
    lines = text.split("\n")
    out, bodies = [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        if "<<" not in line:
            continue
        try:
            toks = lex(line)
        except Blocked:
            continue
        markers = [(t == "<<-", toks[k + 1]) for k, t in enumerate(toks)
                   if t in HEREDOC_OPS and k + 1 < len(toks)]
        for strip_tabs, marker in markers:
            body = []
            while i < len(lines):
                cand = lines[i].lstrip("\t") if strip_tabs else lines[i]
                i += 1
                if cand == marker:
                    break
                body.append(lines[i - 1])
            bodies.append("\n".join(body))
    return "\n".join(out), bodies


def extract_substitutions(text):
    """Inner commands of $( ), backticks, <( ) and >( ), quote-aware."""
    inner = []
    i, n = 0, len(text)
    in_single = in_double = False
    while i < n:
        c = text[i]
        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == '"':
            in_double = not in_double
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if c == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise Blocked("backtick non ferme, blocage par defaut.")
            inner.append(text[i + 1:j])
            i = j + 1
            continue
        opener = text[i:i + 2]
        if opener == "$(" or (opener in ("<(", ">(") and not in_double):
            j, depth = i + 2, 1
            sq = dq = False
            while j < n and depth:
                d = text[j]
                if sq:
                    sq = d != "'"
                elif d == "\\":
                    j += 1
                elif d == "'" and not dq:
                    sq = True
                elif d == '"':
                    dq = not dq
                elif not dq and d == "(":
                    depth += 1
                elif not dq and d == ")":
                    depth -= 1
                j += 1
            if depth:
                raise Blocked("substitution non fermee, blocage par defaut.")
            inner.append(text[i + 2:j - 1])
            i = j
            continue
        i += 1
    return inner


def read_text_file(path, ctx, strict):
    """Text content of a script the command would run, or None when it does not
    exist or is a binary. strict: a text script too large to check is refused."""
    p = ctx.resolve(path)
    if not os.path.isfile(p):
        return None
    with open(p, "rb") as f:
        head = f.read(4096)
        if b"\0" in head or head.startswith(b"\x7fELF"):
            return None
        rest = f.read(MAX_SCRIPT_BYTES)
    data = head + rest
    if len(data) > MAX_SCRIPT_BYTES:
        if strict:
            raise Blocked("script trop volumineux pour etre controle (%s)." % path)
        return None
    return data.decode("utf-8", errors="replace")


def check_command(text, ctx, depth=0):
    if depth > MAX_DEPTH:
        raise Blocked("imbrication trop profonde, blocage par defaut.")
    if len(text) > MAX_COMMAND_CHARS:
        raise Blocked("commande trop longue pour etre controlee (%d caracteres) : ecris les "
                      "donnees avec l'outil Write." % len(text))
    text = decode_ansi_c(text)
    if HOOK_CANARY in text:
        raise Blocked("canari du hook : le hook est actif.")
    if re.search(r"/dev/(tcp|udp)/", text):
        raise Blocked("ouverture de socket via /dev/tcp ou /dev/udp.")
    for sub in extract_substitutions(text):
        check_command(sub, ctx, depth + 1)
    stripped, bodies = split_heredocs(text)
    tokens = lex(stripped)
    if sum(1 for t in tokens if t in HEREDOC_OPS) != len(bodies):
        raise Blocked("heredoc ambigu (operateurs et corps ne correspondent pas).")
    body_iter = iter(bodies)
    segment, prev_sep = [], None
    for tok in tokens + [";"]:
        if tok in SEPARATORS:
            if segment:
                check_segment(segment, ctx, depth, body_iter, piped=prev_sep in ("|", "|&"))
            segment, prev_sep = [], tok
        else:
            segment.append(tok)


def check_segment(tokens, ctx, depth, body_iter, piped):
    words, heredoc_bodies, herestrings = [], [], []
    k = 0
    while k < len(tokens):
        t = tokens[k]
        nxt = tokens[k + 1] if k + 1 < len(tokens) else None
        if t in HEREDOC_OPS:
            heredoc_bodies.append(next(body_iter, ""))
            k += 2
            continue
        if t in HERESTRING_OPS:
            if nxt is not None:
                herestrings.append(nxt)
            k += 2
            continue
        if t in REDIRECTS:
            if nxt is None:
                raise Blocked("redirection sans cible.")
            nxt = substitute_vars(nxt, ctx)
            if any(is_secret_path(v) for v in word_variants(nxt, ctx)):
                raise Blocked("redirection depuis ou vers un fichier secret (%s)." % nxt)
            if t not in ("<", "<&", ">&") and not nxt.isdigit():
                ctx.writable(nxt)
            k += 2
            continue
        if t.isdigit() and nxt in REDIRECTS:
            k += 1
            continue
        words.append(t)
        k += 1
    for hs in herestrings:
        if any(is_secret_path(v) for v in word_variants(substitute_vars(hs, ctx), ctx)):
            raise Blocked("herestring vers un fichier secret.")
    raw_head = next((w for w in words if not is_assignment(w) and w not in LEADING_KEYWORDS),
                    None)
    if raw_head is not None and raw_head.startswith("$"):
        raise Blocked("commande issue d'une variable (%s) : appelle le programme par son "
                      "nom." % raw_head[:40])
    for w in words:
        m = SECRET_VAR_RE.search(w)
        if m and m.group(1).upper() not in ("PWD", "OLDPWD"):
            raise Blocked("reference a une variable secrete ($%s)." % m.group(1))
    words = [substitute_vars(w, ctx) for w in words]
    for w in words:
        for v in word_variants(w, ctx):
            if is_secret_path(v):
                raise Blocked("acces a un fichier secret (%s). Les secrets ne passent "
                              "jamais dans la sortie des outils ; utilise "
                              ".claude/scripts/redacted_secret_scan.py." % w[:80])
    assignments = []
    while words and (is_assignment(words[0]) or words[0] in LEADING_KEYWORDS):
        if is_assignment(words[0]):
            assignments.append(words[0])
        words = words[1:]
    command_name = exe_name(words[0]) if words else None
    for a in assignments:
        check_env_name(a.split("=", 1)[0].rstrip("+"), command_name, a.split("=", 1)[1], ctx)
        if not words:
            name, value = a.split("=", 1)
            if "$(" not in value and "`" not in value:
                ctx.vars[name.rstrip("+")] = value
    while words and words[0] in LEADING_KEYWORDS:
        words = words[1:]
    if not words:
        for body in heredoc_bodies:
            data_heredoc_check(body)
        return
    if words[0] in SKIP_SEGMENT_KEYWORDS:
        return
    check_words(words, ctx, depth, heredoc_bodies, herestrings, piped)


def data_heredoc_check(body):
    if DATA_HEREDOC_DANGER_RE.search(body):
        raise Blocked("heredoc contenant une commande sensible (utilise l'outil Write "
                      "pour ecrire un fichier de donnees).")


def check_words(words, ctx, depth, heredoc_bodies=(), herestrings=(), piped=False):
    name = exe_name(words[0])
    fam = family(name)
    args = words[1:]

    if name in PRIVILEGE:
        raise Blocked("elevation de privileges (%s)." % name)
    if name in GIT_HOSTING_CLIS:
        raise Blocked("CLI d'hebergement git (%s) : aucune action sur GitHub ou GitLab "
                      "pendant une passe." % name)
    if name in NETWORK or name.startswith("ssh"):
        raise Blocked("outil reseau (%s)." % name)
    if name == "openssl" and args and args[0] in ("s_client", "s_server", "s_time"):
        raise Blocked("connexion reseau via openssl.")
    if name in LIVE_SYSTEMS:
        raise Blocked("systeme vivant ou outil d'infrastructure (%s) : la flotte analyse "
                      "des fichiers, jamais des systemes en marche." % name)
    if name in DESTRUCTIVE or name.startswith("mkfs"):
        raise Blocked("commande destructive (%s)." % name)
    if name in EDITORS:
        raise Blocked("editeur interactif (%s) : utilise les outils Edit ou Write." % name)
    if name == "env" and not [a for a in args if not a.startswith("-")
                              and not is_assignment(a)]:
        raise Blocked("affichage de l'environnement : il peut contenir des secrets.")
    if name in ("read", "mapfile", "readarray"):
        for a in args:
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", a):
                check_env_name(a)
    if name == "printf" and any(a == "-v" or a.startswith("-v") for a in args):
        raise Blocked("printf -v : affectation de variable non controlable.")
    if name in ("declare", "typeset", "local", "readonly") and any(
            a.startswith("-") and "n" in a[1:] for a in args):
        raise Blocked("reference de nom (declare -n) : indirection non controlable.")
    if name == "set" and ("allexport" in args or any(
            a.startswith("-") and not a.startswith("--") and "a" in a[1:] for a in args)):
        raise Blocked("set -a / allexport : exporte implicitement toute variable.")
    if name in ("env", "export", "declare", "typeset", "readonly", "local"):
        inner = None
        if name == "env":
            ci = wrapper_command_index("env", args)
            inner = exe_name(args[ci]) if ci is not None else None
        for a in args:
            if is_assignment(a):
                check_env_name(a.split("=", 1)[0].rstrip("+"), inner, a.split("=", 1)[1], ctx)
            elif name != "env" and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", a):
                check_env_name(a)
        if name == "env":
            for idx, a in enumerate(args):
                if a in ("-u", "--unset") and idx + 1 < len(args):
                    check_env_name(args[idx + 1])
    if name == "printenv":
        if not args or any(SECRET_NAME_RE.match(a) for a in args):
            raise Blocked("affichage de l'environnement ou d'une variable secrete.")
        return
    if name == "set" and not args:
        raise Blocked("affichage des variables du shell.")
    if name == "export" and (not args or args == ["-p"]):
        raise Blocked("affichage des variables exportees.")
    if name in ("declare", "typeset") and (not args or (all(a.startswith("-") for a in args)
                                                        and set(args) & {"-p", "-x"})):
        raise Blocked("affichage des variables du shell.")
    if name == "compgen" and set(args) & {"-v", "-e"}:
        raise Blocked("affichage des variables du shell.")
    if name in ("source", "."):
        if args:
            body = read_text_file(args[0], ctx, strict=True)
            if body is None and not os.path.exists(ctx.resolve(args[0])):
                raise Blocked("fichier %s absent au moment du controle." % args[0][:60])
            if body is not None:
                check_command(body, ctx, depth + 1)
        return
    if name == "eval":
        check_command(" ".join(args), ctx, depth + 1)
        return

    if name == "git" or name.startswith("git-"):
        check_git(name, args, ctx)
        for body in heredoc_bodies:
            data_heredoc_check(body)
        return

    if name in ARCHIVE_EXTRACTORS or (name in ("tar", "bsdtar", "gtar") and tar_extracts(args)) \
            or (name in ("cpio",) and set(args) & {"-i", "--extract", "-p", "--pass-through"}) \
            or (name in ("7z", "7za", "7zr") and args[:1] and args[0] in ("x", "e")) \
            or (name in ("xxd",) and "-r" in args):
        raise Blocked("extraction d'archive ou application de patch (%s) : les chemins ecrits "
                      "viennent du contenu, pas de la commande." % name)
    if name in ("tar", "bsdtar", "gtar"):
        for idx, a in enumerate(args):
            if a in ("-f", "--file") and idx + 1 < len(args):
                ctx.writable(args[idx + 1])
            elif a.startswith("--file="):
                ctx.writable(a.split("=", 1)[1])
        if args and not args[0].startswith("-") and "f" in args[0] and len(args) > 1:
            ctx.writable(args[1])
    if name in ("split", "csplit"):
        raise Blocked("%s : ecrit des fichiers derives d'un prefixe." % name)
    for target in output_options(name, args):
        ctx.writable(target)
    if fam in PACKAGE_MANAGERS_ALWAYS:
        raise Blocked("gestionnaire de paquets (%s) : aucune installation pendant une "
                      "passe." % name)
    if fam == "bun":
        for code in inline_codes("bun", args):
            inline_check("bun", code)
    if fam in PACKAGE_MANAGERS_VERBS:
        rest = check_package_manager(fam, args)
        if rest:
            check_words(rest, ctx, depth + 1)
        return
    if name in ("make", "gmake", "just", "task", "invoke", "rake", "mage"):
        targets = [a for a in args if not a.startswith("-") and "=" not in a]
        if any(RELEASE_RE.search(t) for t in targets):
            raise Blocked("cible de build de type deploiement ou publication (%s)."
                          % " ".join(targets))
        return

    if name == "rm":
        check_rm(args, ctx)
    if name in WRITE_ALL_ARGS:
        for a in args:
            if not a.startswith("-"):
                ctx.writable(a)
    if name == "cp" and any(a in ("-s", "-l", "--link", "--symbolic-link") or
                            (a.startswith("-") and not a.startswith("--") and set(a[1:]) & set("sl"))
                            for a in args):
        raise Blocked("cp en mode lien (symbolique ou physique).")
    if name in WRITE_LAST_ARG:
        for a in args:
            if not a.startswith("-"):
                ctx.protected(a)
        target = None
        for idx, a in enumerate(args):
            if a in ("-t", "--target-directory") and idx + 1 < len(args):
                target = args[idx + 1]
            elif a.startswith("--target-directory="):
                target = a.split("=", 1)[1]
        dests = [a for a in args if not a.startswith("-")]
        if target:
            ctx.writable(target)
        elif dests:
            ctx.writable(dests[-1])
    if name in ("sed", "perl") and any(a == "-i" or a.startswith(("-i", "--in-place"))
                                       or (name == "perl" and a.startswith("-") and
                                           not a.startswith("--") and "i" in a[1:])
                                       for a in args):
        for f in in_place_files(name, args):
            ctx.writable(f)
    if name in ("sed", "gsed"):
        check_sed(args, ctx)
    if name in ("cd", "pushd"):
        check_cd(args, ctx)
        return
    if name == "find":
        check_find(args, ctx, depth)
        return
    if name in ("grep", "egrep", "fgrep", "rg", "ag", "ack", "ugrep", "zgrep"):
        check_grep(args)
        return
    if name in AWKS:
        check_awk(args, ctx)
        return
    if name in SHELLS:
        check_shell(args, ctx, depth, heredoc_bodies, herestrings, piped)
        return
    if fam in INTERPRETERS:
        check_interpreter(fam, args, ctx, depth, heredoc_bodies, herestrings, piped)
        return
    if name in WRAPPERS:
        check_wrapper(name, args, ctx, depth)
        return
    if "/" in words[0]:
        if not os.path.exists(ctx.resolve(words[0])):
            raise Blocked("programme %s absent au moment du controle : ecris-le, puis "
                          "lance-le dans une commande separee." % words[0][:60])
        body = read_text_file(words[0], ctx, strict=False)
        if body is not None:
            first = body.split("\n", 1)[0]
            if first.startswith("#!") and re.search(r"\b(ba|z|da|k|mk)?sh\b", first):
                check_command(body, ctx, depth + 1)
            elif SCRIPT_FILE_DANGER_RE.search(body):
                raise Blocked("script executable contenant une commande sensible (%s)."
                              % words[0])
    for body in heredoc_bodies:
        data_heredoc_check(body)


ARCHIVE_EXTRACTORS = {"unzip", "funzip", "unrar", "unar", "jar", "patch", "ar", "rpm2cpio",
                      "dpkg-deb", "bsdcpio"}
SHORT_O_OUTPUT = {"sort", "shuf", "pip-audit", "semgrep", "opengrep", "bandit", "trivy",
                  "pandoc", "gcc", "cc", "clang", "g++", "c++", "go", "rustc", "msgfmt", "dot",
                  "gitleaks", "jq", "yq", "uniq", "base64"}
LONG_OUTPUT = ("--output", "--output-file", "--outfile", "--out", "--report-path", "--log-file",
               "--logfile", "--output-dir", "--outdir", "--out-dir", "--result-file",
               "--json-output", "--sarif-output", "--junitxml", "--cov-report")


def output_options(name, args):
    """Paths written by a program because of its own options (-o, --output=...)."""
    out = []
    if name == "openssl":
        for i, a in enumerate(args):
            if a in ("-out", "-keyout", "-certout", "-signature", "-sigout") and i + 1 < len(args):
                out.append(args[i + 1])
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else None
        key = a.split("=", 1)[0]
        if key in LONG_OUTPUT:
            if "=" in a:
                out.append(a.split("=", 1)[1])
            elif nxt is not None:
                out.append(nxt)
        elif name in SHORT_O_OUTPUT and a == "-o" and nxt is not None:
            out.append(nxt)
        elif name in SHORT_O_OUTPUT and a.startswith("-o") and len(a) > 2 and name != "sort":
            out.append(a[2:])
    cleaned = []
    for o in out:
        o = o.split(":", 1)[1] if (name == "pytest" or key == "--cov-report") and ":" in o else o
        if o and not o.startswith("-") and o not in ("term", "term-missing", "html", "xml"):
            cleaned.append(o)
    return cleaned


def tar_extracts(args):
    if not args:
        return False
    first = args[0]
    if not first.startswith("-") and "x" in first:
        return True
    return any(a in ("-x", "--extract", "--get") or
               (a.startswith("-") and not a.startswith("--") and "x" in a[1:]) for a in args)


def check_awk(args, ctx):
    programs, positional, i, inplace = [], [], 0, False
    while i < len(args):
        a = args[i]
        if a in ("-f", "--file", "-E", "--exec") and i + 1 < len(args):
            body = read_text_file(args[i + 1], ctx, strict=True)
            if body is None:
                raise Blocked("programme awk illisible ou lu depuis un flux (%s)."
                              % args[i + 1][:60])
            programs.append(body)
            i += 2
            continue
        if a in ("-l", "--load") or a.startswith(("--load=", "-l")) and len(a) > 2:
            raise Blocked("awk --load : chargement d'extension binaire.")
        if a in ("-i", "--include") and i + 1 < len(args):
            if not args[i + 1].startswith("inplace"):
                raise Blocked("awk --include d'un fichier de programme non controle.")
            inplace = True
            i += 2
            continue
        if a.startswith("--include=") or (a.startswith("-i") and len(a) > 2):
            if "inplace" not in a:
                raise Blocked("awk --include d'un fichier de programme non controle.")
            inplace = True
        elif a in ("-v", "--assign", "-F", "--field-separator") and i + 1 < len(args):
            i += 2
            continue
        elif not a.startswith("-"):
            positional.append(a)
        i += 1
    if not programs and positional:
        programs.append(positional.pop(0))
    for prog in programs:
        if re.search(r"@(include|load|namespace)\b", prog):
            raise Blocked("awk @include/@load : programme ou extension non controle.")
        if AWK_DANGER_RE.search(prog):
            raise Blocked("programme awk qui execute des commandes, ecrit, lit un fichier "
                          "par redirection ou ouvre le reseau.")
    if inplace:
        for f in positional:
            if "=" not in f:
                ctx.writable(f)


def check_sed(args, ctx):
    if "--sandbox" in args:
        return
    scripts, positional, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "--expression") and i + 1 < len(args):
            scripts.append(args[i + 1])
            i += 2
            continue
        if a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
        elif a in ("-f", "--file") and i + 1 < len(args):
            body = read_text_file(args[i + 1], ctx, strict=True)
            if body is None:
                raise Blocked("script sed illisible ou lu depuis un flux (%s)." % args[i + 1][:60])
            scripts.append(body)
            i += 2
            continue
        elif a.startswith("--file="):
            body = read_text_file(a.split("=", 1)[1], ctx, strict=True)
            if body is None:
                raise Blocked("script sed illisible ou lu depuis un flux.")
            scripts.append(body)
        elif a in ("-l", "--line-length") and i + 1 < len(args):
            i += 2
            continue
        elif not a.startswith("-"):
            positional.append(a)
        i += 1
    if not scripts and positional:
        scripts.append(positional[0])
    for script in scripts:
        for m in SED_S_RE.finditer(script):
            flags = re.match(r"[A-Za-z0-9]*", m.group(4).strip()).group(0)
            if set(flags) & set("ewW"):
                raise Blocked("sed s///%s : execution de commande ou ecriture de fichier."
                              % flags)
        for m in SED_CMD_RE.finditer(script):
            cmd, arg = m.group(1), m.group(2).strip()
            if cmd in "eEwW":
                raise Blocked("sed commande '%s' : execution ou ecriture de fichier." % cmd)
            if cmd in "rRF" and arg and is_secret_path(arg):
                raise Blocked("sed lit un fichier secret (%s)." % arg[:60])


def in_place_files(name, args):
    """Files edited in place by sed -i / perl -i (the script expression excluded)."""
    value_opts = {"-e", "--expression", "-f", "--file"} if name == "sed" else {"-e", "-E"}
    files, has_script_opt, i = [], False, 0
    while i < len(args):
        a = args[i]
        if a in value_opts:
            has_script_opt = True
            i += 2
            continue
        if a.startswith(("--expression=", "--file=")):
            has_script_opt = True
        elif name == "perl" and a.startswith("-") and not a.startswith("--") and \
                a.endswith("e") and len(a) > 2:
            has_script_opt = True
            i += 2
            continue
        elif not a.startswith("-"):
            files.append(a)
        i += 1
    if not has_script_opt and files:
        files = files[1:]
    return files


def check_git(name, args, ctx):
    if name.startswith("git-"):
        sub, rest = name[4:], args
    else:
        i = 0
        while i < len(args):
            t = args[i]
            if t == "-c":
                key = (args[i + 1] if i + 1 < len(args) else "").split("=", 1)[0].lower()
                if key.startswith(GIT_DANGEROUS_CONFIG):
                    raise Blocked("git -c %s : configuration git a risque." % key)
                i += 2
                continue
            if t in ("--config-env", "--exec-path") or t.startswith(("--config-env=",
                                                                    "--exec-path=")):
                raise Blocked("option globale git interdite (%s)." % t.split("=")[0])
            if t in ("-C", "--git-dir", "--work-tree") and i + 1 < len(args):
                check_repo_path(args[i + 1], ctx)
                i += 2
                continue
            if t.startswith(("--git-dir=", "--work-tree=")):
                check_repo_path(t.split("=", 1)[1], ctx)
                i += 1
                continue
            if t in GIT_OPTS_WITH_VALUE:
                i += 2
                continue
            if t.startswith("-"):
                i += 1
                continue
            break
        if i >= len(args):
            return
        sub, rest = args[i].lower(), args[i + 1:]
    if sub not in GIT_ALLOWED:
        raise Blocked("git %s : hors de la liste autorisee (lecture, add, commit, branche "
                      "locale). Push, fetch, clone, config, remote, merge, rebase et "
                      "reecriture d'historique sont des actions humaines." % sub)
    flags = [a for a in rest if a.startswith("-")]
    short = "".join(a[1:] for a in flags if not a.startswith("--"))
    positional = [a for a in rest if not a.startswith("-")]

    def has(*opts):
        return any(a in opts or (a.split("=", 1)[0] in opts and "=" in a) for a in rest)

    if sub == "branch" and (set(short) & set("DfMC") or has("--force")):
        raise Blocked("git branch force (suppression, deplacement ou renommage force).")
    if sub == "tag" and (set(short) & set("df") or has("--delete", "--force")):
        raise Blocked("git tag : suppression ou ecrasement de tag.")
    if sub == "stash" and positional and positional[0].lower() in ("drop", "clear"):
        raise Blocked("git stash drop/clear : perte de travail.")
    if sub == "remote" and positional and positional[0].lower() != "get-url":
        raise Blocked("git remote %s : modification ou interrogation du depot distant."
                      % positional[0])
    if sub == "worktree" and (not positional or positional[0].lower() != "list"):
        raise Blocked("git worktree : seule la lecture (list) est autorisee.")
    if sub == "reflog" and positional and positional[0].lower() in ("expire", "delete",
                                                                     "drop"):
        raise Blocked("git reflog expire/delete : perte de l'historique de recuperation.")
    if sub == "notes" and positional and positional[0].lower() not in ("show", "list"):
        raise Blocked("git notes : seule la lecture est autorisee.")
    if sub == "archive" and has("--remote"):
        raise Blocked("git archive --remote : acces au depot distant.")
    if sub == "commit" and has("--amend"):
        raise Blocked("git commit --amend : reecriture d'historique.")
    if sub == "reset" and has("--hard", "--merge", "--keep"):
        raise Blocked("git reset --hard/--merge/--keep : perte de travail.")
    if sub == "restore" and (not has("--staged", "-S") or has("--worktree", "-W")):
        raise Blocked("git restore sur l'arbre de travail : perte de modifications. Pour "
                      "abandonner un essai : git stash push -m abandon-<id>.")
    if sub == "switch" and (set(short) & set("fC") or has("--force", "--discard-changes",
                                                         "--force-create")):
        raise Blocked("git switch force : perte de modifications.")
    if sub == "checkout":
        if set(short) & set("fBp") or has("--force", "--ours", "--theirs", "--patch",
                                          "--pathspec-from-file", "--overwrite-ignore"):
            raise Blocked("git checkout force ou sur fichiers : perte de modifications.")
        if "--" in rest or any(p in (".", ":/", "*") for p in positional):
            raise Blocked("git checkout sur des chemins : perte de modifications. Pour "
                          "abandonner un essai : git stash push -m abandon-<id>.")
        if "b" not in short and len(positional) > 1:
            raise Blocked("git checkout <rev> <chemins> : ecrase des fichiers.")
    if sub == "add" and (set(short) & set("Af") or has("--all", "--force")
                         or any(p in (".", ":/", "*") for p in positional)):
        raise Blocked("git add global ou force : indexe des fichiers non voulus (.claude/, "
                      "secrets). Nomme explicitement les fichiers modifies.")
    if sub in ("rm", "mv") and ("f" in short or has("--force")):
        raise Blocked("git %s --force." % sub)
    if sub == "grep":
        check_grep(rest)
    for i, a in enumerate(rest):
        nxt = rest[i + 1] if i + 1 < len(rest) else None
        if a.startswith("--output="):
            ctx.writable(a.split("=", 1)[1])
        elif a in ("--output", "-o", "--output-directory") and nxt is not None and \
                sub in ("log", "show", "diff", "format-patch", "archive", "whatchanged",
                        "range-diff", "diff-tree", "diff-files", "diff-index", "shortlog"):
            ctx.writable(nxt)
        elif a.startswith("-o") and len(a) > 2 and sub in ("format-patch", "archive"):
            ctx.writable(a[2:])


def check_repo_path(path, ctx):
    if ctx.project is None:
        return
    if not ctx.contained(ctx.resolve(path)):
        raise Blocked("git sur un autre depot que le projet (%s) : une passe ne couvre "
                      "qu'un seul repo." % path[:80])


def check_cd(args, ctx):
    targets = [a for a in args if a != "-" and not (a.startswith("-") and len(a) > 1)]
    if not targets:
        raise Blocked("cd sans destination explicite (repertoire personnel).")
    t = targets[0]
    if t.startswith(("$", "~")) or "`" in t or "$(" in t:
        raise Blocked("cd vers une destination non resolue (%s)." % t[:60])
    rp = ctx.resolve(t)
    if not ctx.contained(rp):
        raise Blocked("cd hors du projet et de /tmp/sweep (%s) : une passe ne couvre "
                      "qu'un seul repo." % t[:80])
    ctx.cwd = rp


def check_rm(args, ctx):
    opts = [a for a in args if a.startswith("-") and a != "--"]
    if not any(a in ("--recursive", "--force") or
               (not a.startswith("--") and set(a[1:]) & set("rRf")) for a in opts):
        return
    paths = [a for a in args if not a.startswith("-")]
    if paths and all(ctx.in_scratch(p) for p in paths):
        return
    raise Blocked("rm recursif ou force hors de /tmp/sweep.")


def check_find(args, ctx, depth):
    roots = []
    for a in args:
        if a.startswith("-") or a in ("(", ")", "!"):
            break
        roots.append(a)
    if "-delete" in args and not (roots and all(ctx.in_scratch(r) for r in roots)):
        raise Blocked("find -delete hors de /tmp/sweep.")
    i = 0
    while i < len(args):
        if args[i] in ("-exec", "-execdir", "-ok", "-okdir"):
            j = i + 1
            inner = []
            while j < len(args) and args[j] not in (";", "\\;", "+"):
                inner.append(args[j])
                j += 1
            if inner:
                check_words(inner, ctx, depth + 1)
            i = j
        i += 1


def check_grep(args):
    for a in args:
        if a in ("--files-with-matches", "--files-without-match", "--count", "--quiet",
                 "--silent", "--count-matches", "--files", "--name-only", "-l", "-L",
                 "-c", "-q"):
            return
        if a.startswith("-") and not a.startswith("--") and set(a[1:]) & set("lLcq"):
            return
    for a in args:
        if SECRET_LITERAL_RE.search(a):
            raise Blocked("grep en mode contenu sur un motif de secret : la valeur "
                          "s'afficherait en clair. Utilise -l / -c ou "
                          ".claude/scripts/redacted_secret_scan.py.")


def check_package_manager(fam, args):
    """Raise for installs and releases. Returns a command to check further when the
    package manager only runs another program (bundle exec)."""
    positional = [a for a in args if not a.startswith("-")]
    if fam in ("bundle", "bundler") and positional[:1] == ["exec"]:
        idx = args.index("exec")
        return args[idx + 1:]
    if fam == "yarn" and not positional:
        raise Blocked("yarn sans argument installe les dependances.")
    if fam == "uv" and positional[:1] == ["run"] and "--no-sync" not in args \
            and "--offline" not in args:
        raise Blocked("uv run synchronise et installe les dependances (ajoute --offline).")
    if fam == "uv" and positional[:1] == ["pip"]:
        positional = positional[1:]
    if fam in ("npm", "pnpm", "yarn", "bun") and positional[:1] in (["run"], ["run-script"]):
        if len(positional) > 1 and RELEASE_RE.search(positional[1]):
            raise Blocked("script de type deploiement ou publication (%s)." % positional[1])
        return None
    if fam == "go" and (positional[:1] in (["get"], ["install"])
                        or positional[:2] == ["mod", "download"]):
        raise Blocked("go get/install : telechargement de dependances.")
    if positional and positional[0].lower() in PACKAGE_VERBS:
        raise Blocked("%s %s : aucune installation, mise a jour ou publication pendant une "
                      "passe." % (fam, positional[0]))
    if positional and RELEASE_RE.search(positional[0]):
        raise Blocked("commande de type deploiement ou publication (%s %s)."
                      % (fam, positional[0]))
    return None


SHELL_VALUE_OPTS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}


def check_shell(args, ctx, depth, heredoc_bodies, herestrings, piped):
    c_index = None
    for idx, a in enumerate(args):
        if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]):
            c_index = idx
            break
    if c_index is not None:
        commands = [a for a in args[c_index + 1:] if not a.startswith(("-", "+"))]
        if not commands:
            raise Blocked("shell -c sans commande.")
        for cmd in commands:
            check_command(cmd, ctx, depth + 1)
        return
    for s in herestrings:
        check_command(s, ctx, depth + 1)
    for body in heredoc_bodies:
        check_command(body, ctx, depth + 1)
    script, i = None, 0
    while i < len(args):
        a = args[i]
        if a in SHELL_VALUE_OPTS:
            i += 2
            continue
        if a == "-s" or a == "-":
            break
        if a.startswith(("-", "+")):
            i += 1
            continue
        script = a
        break
    if script is not None:
        body = read_text_file(script, ctx, strict=True)
        if body is None and not os.path.exists(ctx.resolve(script)):
            raise Blocked("script %s absent au moment du controle : ecris-le, puis lance-le "
                          "dans une commande separee." % script[:60])
        if body is not None:
            check_command(body, ctx, depth + 1)
        return
    if piped:
        raise Blocked("contenu envoye a un shell par un pipe : construction a proscrire.")


INLINE_LONG = {"node": ("--eval", "--print", "-e", "-p"), "nodejs": ("--eval", "--print",
                                                                     "-e", "-p"),
               "bun": ("--eval", "--print", "-e", "-p"),
               "pwsh": ("-c", "-command", "-Command", "-EncodedCommand", "-e"),
               "powershell": ("-c", "-command", "-Command", "-EncodedCommand", "-e")}
INLINE_LETTERS = {"python": "c", "perl": "eE", "ruby": "e", "php": "r", "lua": "e",
                  "rscript": "e", "julia": "e", "osascript": "e"}
ATTACHED_VALUE_LETTERS = {"python": "WX", "perl": "MmIFxC0ldD", "ruby": "IrCEFKTWx0l",
                          "php": "cdz", "lua": "lW"}
VALUE_OPTS = {"python": {"-W", "-X"},
              "node": {"--title", "--input-type", "-C", "--conditions", "--env-file"},
              "nodejs": {"--title", "--input-type", "-C", "--conditions", "--env-file"},
              "bun": {"--cwd", "--env-file"},
              "perl": {"-I", "-M", "-m"},
              "ruby": {"-I", "-r", "-C", "-E", "-F", "-K"},
              "php": {"-c", "-d", "-z", "-t"},
              "lua": {"-l"}}
PRELOAD_OPTS = {"node": ("-r", "--require", "--import", "--loader", "--experimental-loader"),
                "nodejs": ("-r", "--require", "--import", "--loader", "--experimental-loader"),
                "bun": ("-r", "--preload", "--require"),
                "ruby": ("-r",), "perl": ("-M", "-m")}


PYTHON_WRITER_MODULES = {"json.tool", "zipfile", "tarfile", "gzip", "bz2", "lzma",
                         "compileall", "py_compile", "base64", "uu", "quopri", "shutil"}


def check_include_paths(fam, args, ctx):
    """perl/ruby -I and ruby -r path: code loaded from a directory or file the sweep
    may have written. Include paths must stay inside the project (never the scratch
    area); a required file path is inspected like a script."""
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a == "-I" or (a.startswith("-I") and len(a) > 2):
            path = a[2:] if len(a) > 2 else nxt
            rp = ctx.resolve(path)
            if not ctx.project or not under(rp, ctx.project) or \
                    any(under(rp, r) for r in ctx.scratch_roots):
                raise Blocked("%s -I hors du projet (%s)." % (fam, path[:60]))
        if fam == "ruby" and (a == "-r" or (a.startswith("-r") and len(a) > 2)):
            target = a[2:] if len(a) > 2 else nxt
            if "/" in target or target.startswith(".") or target.endswith(".rb"):
                check_script_file(fam, target, [], ctx)


def inline_check(fam, code):
    if INLINE_CODE_DANGER_RE.search(code):
        raise Blocked("code en ligne (%s) avec acces reseau, processus, environnement, "
                      "secrets, ecriture ou suppression de fichiers, git distant ou "
                      "execution dynamique." % fam)


def inline_codes(fam, args):
    """Inline code strings passed to an interpreter, including clustered short
    options (perl -ne, ruby -pe, python -Bc)."""
    codes = []
    letters = INLINE_LETTERS.get(fam, "")
    longs = INLINE_LONG.get(fam, ())
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a in longs:
            codes.append(nxt)
            continue
        if "=" in a and a.split("=", 1)[0] in longs:
            codes.append(a.split("=", 1)[1])
            continue
        if not letters or not a.startswith("-") or a.startswith("--") or len(a) < 2:
            continue
        if a[1] in ATTACHED_VALUE_LETTERS.get(fam, ""):
            continue
        for k, ch in enumerate(a[1:]):
            if ch in letters:
                rest = a[k + 2:]
                codes.append(rest if rest else nxt)
                break
    return codes


def check_interpreter(fam, args, ctx, depth, heredoc_bodies, herestrings, piped):
    if fam == "deno":
        positional = [a for a in args if not a.startswith("-")]
        sub = positional[0] if positional else ""
        if sub in ("install", "upgrade", "publish", "add", "compile", "x", "jupyter"):
            raise Blocked("deno %s." % sub)
        if sub == "eval":
            inline_check(fam, positional[1] if len(positional) > 1 else "")
            return
        target = positional[1] if sub == "run" and len(positional) > 1 else sub
        if re.match(r"^(https?|npm|jsr):", target or ""):
            raise Blocked("deno execute du code distant (%s)." % target[:60])
        if target:
            check_script_file(fam, target, [], ctx)
        return
    if fam in ("pwsh", "powershell") and any(a.lower().startswith(("-enc", "-ec", "-e"))
                                             and a.lower() not in ("-executionpolicy",)
                                             for a in args):
        raise Blocked("powershell -EncodedCommand : code illisible.")
    if fam in ("perl", "ruby"):
        check_include_paths(fam, args, ctx)
    for idx, a in enumerate(args):
        key = a.split("=", 1)[0]
        if key in PRELOAD_OPTS.get(fam, ()):
            target = a.split("=", 1)[1] if "=" in a else (args[idx + 1] if idx + 1 < len(args) else "")
            if fam in ("ruby", "perl"):
                continue
            if target and not target.startswith("-"):
                check_script_file(fam, target, [], ctx)
    codes = inline_codes(fam, args)
    for code in codes:
        inline_check(fam, code)
    if codes:
        return
    i = 0
    while i < len(args):
        a = args[i]
        if fam == "python" and a == "-m" and i + 1 < len(args):
            mod = args[i + 1]
            rest = [x for x in args[i + 2:] if not x.startswith("-")]
            if mod in ("zipfile", "tarfile") and set(args[i + 2:]) & {"-e", "--extract"}:
                raise Blocked("python -m %s --extract : chemins ecrits par le contenu." % mod)
            if mod in PYTHON_WRITER_MODULES:
                for x in rest:
                    ctx.writable(x)
            if mod in ("pip", "ensurepip") and rest and rest[0] in PACKAGE_VERBS:
                raise Blocked("python -m pip %s : aucune installation." % rest[0])
            if mod in ("http.server", "smtpd", "pydoc", "webbrowser", "ftplib", "telnetlib"):
                raise Blocked("python -m %s : service ou acces reseau." % mod)
            return
        if a in VALUE_OPTS.get(fam, set()) or a in PRELOAD_OPTS.get(fam, ()):
            i += 2
            continue
        if a.startswith("-") and a != "-":
            i += 1
            continue
        break
    for s_ in herestrings:
        inline_check(fam, s_)
    for body in heredoc_bodies:
        inline_check(fam, body)
    script = args[i] if i < len(args) else None
    if script is None or script == "-":
        if piped:
            raise Blocked("code envoye a %s par un pipe : construction a proscrire." % fam)
        return
    check_script_file(fam, script, args[i + 1:], ctx)


def check_script_file(fam, script, script_args, ctx):
    resolved = ctx.resolve(script)
    if not os.path.exists(resolved):
        raise Blocked("script %s absent au moment du controle : ecris-le, puis lance-le dans "
                      "une commande separee." % script[:60])
    body = read_text_file(script, ctx, strict=False)
    if body is None:
        return
    in_scratch = any(under(resolved, r) for r in ctx.scratch_roots)
    if in_scratch and INLINE_CODE_DANGER_RE.search(body):
        raise Blocked("script %s ecrit dans /tmp/sweep avec acces reseau, processus, "
                      "environnement, secrets ou ecriture de fichiers." % script[:60])
    if SCRIPT_FILE_DANGER_RE.search(body):
        raise Blocked("script %s contenant une commande sensible." % script[:60])
    if os.path.basename(resolved) == "setup.py" and set(script_args) & {
            "install", "develop", "upload", "sdist", "bdist_wheel", "register"}:
        raise Blocked("setup.py install/develop/upload.")


def wrapper_command_index(name, args):
    value_opts, positional_before = WRAPPERS.get(name, (set(), 0))
    i = 0
    while i < len(args):
        a = args[i]
        if name == "env" and is_assignment(a):
            i += 1
            continue
        if a == "--":
            i += 1
            break
        if a.startswith("-") and len(a) > 1:
            i += 2 if (a in value_opts and "=" not in a) else 1
            continue
        break
    i += positional_before
    return i if i < len(args) else None


def check_wrapper(name, args, ctx, depth):
    if name == "command" and args and args[0] in ("-v", "-V"):
        return
    for idx, a in enumerate(args):
        if name == "env" and a in ("-S", "--split-string") and idx + 1 < len(args):
            check_command(args[idx + 1], ctx, depth + 1)
        if name == "env" and a.startswith("--split-string="):
            check_command(a.split("=", 1)[1], ctx, depth + 1)
        if name in ("script", "flock") and idx + 1 < len(args) and (
                a in ("-c", "--command") or (a.startswith("-") and not a.startswith("--")
                                             and "c" in a[1:])):
            check_command(args[idx + 1], ctx, depth + 1)
        if name == "parallel" and a in ("-S", "--sshlogin", "--sshloginfile"):
            raise Blocked("parallel avec execution distante.")
    ci = wrapper_command_index(name, args)
    if ci is not None and name != "script":
        inner = args[ci:]
        if name == "watch" and "-x" not in args and "--exec" not in args:
            check_command(" ".join(inner), ctx, depth + 1)
        else:
            if any(ch.isspace() for ch in inner[0]):
                check_command(inner[0], ctx, depth + 1)
            else:
                if name in INPUT_FED_WRAPPERS:
                    input_fed_check(name, inner)
                check_words(inner, ctx, depth + 1)
    # Safety net when the option parsing above guessed wrong: unambiguous program
    # names anywhere in the arguments are checked as commands.
    checked = ci if (ci is not None and name != "script") else None
    for i, tok in enumerate(args):
        if i == checked or any(ch.isspace() for ch in tok):
            continue
        nm = exe_name(tok)
        if nm in STRICT_ANYWHERE or family(nm) in STRICT_ANYWHERE or \
                nm.startswith(("ssh", "mkfs", "git-")):
            if name in INPUT_FED_WRAPPERS:
                input_fed_check(name, args[i:])
            check_words(args[i:], ctx, depth + 1)


def input_fed_check(name, inner):
    nm = exe_name(inner[0])
    if nm == "git" or nm.startswith("git-"):
        sub = next((a.lower() for a in inner[1:] if not a.startswith("-")), "")
        if nm.startswith("git-"):
            sub = nm[4:]
        if sub not in GIT_READ_ONLY:
            raise Blocked("git alimente par %s (sous-commande '%s') : seules les lectures "
                          "sont autorisees." % (name, sub or "issue de l'entree"))
    if nm in SHELLS or family(nm) in INTERPRETERS:
        raise Blocked("%s qui lance un shell ou un interpreteur." % name)


# --------------------------------------------------------------------------- #
# Tool dispatch
# --------------------------------------------------------------------------- #

def check_payload(payload):
    tool = payload.get("tool_name")
    ti = payload.get("tool_input")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    ctx = Context(cwd, os.environ.get("CLAUDE_PROJECT_DIR"))
    if tool is None or tool == "Bash":
        command = ti.get("command") if isinstance(ti, dict) else None
        if not isinstance(command, str):
            raise Blocked("commande absente ou non textuelle, blocage par defaut.")
        check_command(command, ctx)
        return
    if not isinstance(ti, dict):
        return
    if tool == "Read":
        for key in ("file_path", "path"):
            v = ti.get(key)
            if isinstance(v, str) and is_secret_path(v):
                raise Blocked("lecture d'un fichier secret (%s) : les secrets ne passent "
                              "jamais dans la sortie des outils." % v[:80])
        return
    if tool == "Grep":
        for key in ("path", "glob"):
            v = ti.get(key)
            if isinstance(v, str) and is_secret_path(v):
                raise Blocked("recherche dans un fichier secret (%s)." % v[:80])
        pattern = ti.get("pattern")
        if ti.get("output_mode") == "content" and isinstance(pattern, str) and \
                SECRET_LITERAL_RE.search(pattern):
            raise Blocked("Grep en mode contenu sur un motif de secret : utilise "
                          "files_with_matches ou count, ou "
                          ".claude/scripts/redacted_secret_scan.py.")
        return
    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        for key in ("file_path", "notebook_path", "path"):
            v = ti.get(key)
            if isinstance(v, str):
                if is_secret_path(v):
                    raise Blocked("ecriture dans un fichier secret (%s)." % v[:80])
                ctx.writable(v)
        return


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except Exception:
        sys.stderr.write(PREFIX + "entree illisible, blocage par defaut.")
        return 2
    if not isinstance(payload, dict):
        sys.stderr.write(PREFIX + "payload non conforme, blocage par defaut.")
        return 2
    try:
        check_payload(payload)
    except Blocked as b:
        sys.stderr.write(PREFIX + str(b) + HINT)
        return 2
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except BaseException as exc:  # noqa: BLE001 - fail closed on anything
        try:
            sys.stderr.write(PREFIX + "erreur interne du hook (%s), blocage par defaut."
                             % type(exc).__name__)
        finally:
            code = 2
    sys.exit(code)
