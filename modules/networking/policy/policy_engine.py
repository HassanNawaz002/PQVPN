"""Local-admin-only policy model. No privileged enforcement yet."""
from pathlib import Path
from shared.config import ClientPolicy

def is_selected_executable(policy: ClientPolicy, executable_path: str) -> bool:
    """Classification helper ONLY; does not steer traffic or grant admin rights."""
    normalized = str(Path(executable_path)).casefold()
    selected = normalized in {str(Path(p)).casefold() for p in policy.executable_paths}
    if policy.mode == "all_apps": return True
    if policy.mode == "bypass_selected": return not selected
    return selected
