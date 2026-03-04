"""
Frida helper utilities for runtime hooking of the game process.

Provides common functions for attaching to the game, finding modules,
and injecting JavaScript hooks.
"""
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


PROCESS_NAME = "FishingPlanet.X86_64"
TARGET_MODULE = "GameAssembly.so"


def check_frida_available() -> bool:
    """Check if Frida is installed and available."""
    return FRIDA_AVAILABLE


def is_game_running() -> bool:
    """Check if the game process is currently running."""
    result = subprocess.run(
        ["pgrep", "-f", PROCESS_NAME],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def get_game_pid() -> Optional[int]:
    """Get the PID of the running game process."""
    result = subprocess.run(
        ["pgrep", "-f", PROCESS_NAME],
        capture_output=True, text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return int(result.stdout.strip().splitlines()[0])
    return None


def attach_to_game() -> Optional["frida.core.Session"]:
    """Attach Frida to the running game process."""
    if not FRIDA_AVAILABLE:
        print("[ERROR] Frida is not installed. Run: pip install frida frida-tools")
        return None

    pid = get_game_pid()
    if pid is None:
        print("[ERROR] Game is not running. Start the game first.")
        return None

    print(f"[*] Attaching to PID {pid}...")
    session = frida.attach(pid)
    print(f"[+] Attached to {PROCESS_NAME}")
    return session


def load_script(session: "frida.core.Session", js_code: str,
                on_message: Optional[callable] = None) -> "frida.core.Script":
    """Load and execute a Frida JavaScript script."""
    script = session.create_script(js_code)
    if on_message:
        script.on("message", on_message)
    else:
        script.on("message", _default_message_handler)
    script.load()
    return script


def load_script_file(session: "frida.core.Session", js_path: Path,
                     on_message: Optional[callable] = None) -> "frida.core.Script":
    """Load a Frida script from a .js file."""
    js_code = js_path.read_text()
    return load_script(session, js_code, on_message)


def get_module_base(session: "frida.core.Session", module_name: str = TARGET_MODULE) -> Optional[int]:
    """Get the base address of a loaded module."""
    script = session.create_script(f"""
        var mod = Process.findModuleByName("{module_name}");
        if (mod) {{
            send({{type: "module_base", name: mod.name, base: mod.base.toString(), size: mod.size}});
        }} else {{
            send({{type: "error", message: "Module not found: {module_name}"}});
        }}
    """)

    result = {"base": None}

    def on_msg(message: dict, data: bytes) -> None:
        if message["type"] == "send":
            payload = message["payload"]
            if payload.get("type") == "module_base":
                result["base"] = int(payload["base"], 16) if isinstance(payload["base"], str) else payload["base"]

    script.on("message", on_msg)
    script.load()
    script.unload()
    return result["base"]


def _default_message_handler(message: dict, data: bytes) -> None:
    """Default handler for Frida script messages."""
    if message["type"] == "send":
        payload = message.get("payload", "")
        print(f"[Frida] {payload}")
    elif message["type"] == "error":
        print(f"[Frida ERROR] {message.get('description', message)}")
