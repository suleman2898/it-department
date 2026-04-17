import os
import sys


ALLOWED_EXTENSIONS = {"pcap", "pcapng", "txt", "log", "csv", "json"}


def resource_path(relative_path: str) -> str:
    """
    Works for normal execution and PyInstaller EXE mode.
    """
    try:
        base_path = sys._MEIPASS  # type: ignore[attr-defined]
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def get_app_root() -> str:
    """
    Returns the writable folder for database and uploads.
    In EXE mode, use the folder where the EXE runs, not _MEIPASS.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.abspath(".")


def get_db_path() -> str:
    return os.path.join(get_app_root(), "data.db")


def get_upload_folder() -> str:
    return os.path.join(get_app_root(), "uploads")


def get_ledger_path() -> str:
    return os.path.join(get_app_root(), "ledger", "chain.json")


def ensure_directories() -> None:
    folders = [
        get_upload_folder(),
        os.path.join(get_app_root(), "ledger"),
        os.path.join(get_app_root(), "static"),
        os.path.join(get_app_root(), "templates"),
        os.path.join(get_app_root(), "models"),
        os.path.join(get_app_root(), "database"),
    ]

    for folder in folders:
        os.makedirs(folder, exist_ok=True)

    ledger_path = get_ledger_path()
    if not os.path.exists(ledger_path):
        with open(ledger_path, "w", encoding="utf-8") as f:
            f.write("[]")


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS