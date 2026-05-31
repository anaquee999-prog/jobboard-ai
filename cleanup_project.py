import os
import shutil
import logging
import argparse

TARGET_FOLDER = r"C:\Users\anaqu\OneDrive\เดสก์ท็อป\JOB\jobboard_step10_ai_scam_center"
LOG_FILE = os.path.join(TARGET_FOLDER, "cleanup_actions.log")

UNNECESSARY_FOLDERS = {
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
UNNECESSARY_EXTENSIONS = {".pyc", ".pyo", ".log"}
VENV_FOLDER_NAMES = {"venv", ".venv", "env", ".env"}
SKIP_DIR_NAMES = {"node_modules"}


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="[%(levelname)s] %(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def is_inside_venv(path):
    parts = os.path.normpath(path).split(os.sep)
    return any(part.lower() in VENV_FOLDER_NAMES for part in parts)


def scan_and_collect(target_folder):
    to_delete = []

    for root, dirs, files in os.walk(target_folder, topdown=True):
        # Never recurse into virtual environments or frontend dependencies.
        dirs[:] = [
            d
            for d in dirs
            if d.lower() not in VENV_FOLDER_NAMES and d not in SKIP_DIR_NAMES
        ]

        removable_dirs = [d for d in dirs if d in UNNECESSARY_FOLDERS]
        for d in removable_dirs:
            to_delete.append(os.path.join(root, d))

        # Avoid walking into folders that are already marked for removal.
        dirs[:] = [d for d in dirs if d not in UNNECESSARY_FOLDERS]

        for f in files:
            full_path = os.path.join(root, f)
            if is_inside_venv(full_path):
                continue

            _, ext = os.path.splitext(f)
            if ext.lower() in UNNECESSARY_EXTENSIONS:
                if os.path.abspath(full_path) == os.path.abspath(LOG_FILE):
                    continue
                to_delete.append(full_path)

    return to_delete


def print_dry_run(items):
    if not items:
        print("No unnecessary files/folders found.")
        return

    print("Items found for removal:")
    for item in items:
        print(item)
    print(f"\nTotal: {len(items)} item(s)")


def delete_items(items):
    deleted = 0
    failed = 0

    for item in items:
        try:
            if os.path.isdir(item):
                shutil.rmtree(item)
                logging.info("Deleted folder: %s", item)
            elif os.path.isfile(item):
                os.remove(item)
                logging.info("Deleted file: %s", item)
            deleted += 1
        except Exception as exc:
            failed += 1
            logging.warning("Failed to delete %s: %s", item, exc)
            print(f"Failed to delete {item}: {exc}")

    print(f"Deletion complete. Deleted: {deleted}, Failed: {failed}")


def main():
    parser = argparse.ArgumentParser(description="Clean unnecessary project files/folders safely.")
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Actually delete files/folders after confirmation. Default is dry-run.",
    )
    args = parser.parse_args()

    setup_logging()
    logging.info("=== Cleanup scan started ===")

    if not os.path.isdir(TARGET_FOLDER):
        print(f"Target folder does not exist: {TARGET_FOLDER}")
        logging.error("Target folder does not exist: %s", TARGET_FOLDER)
        return

    to_delete = scan_and_collect(TARGET_FOLDER)
    print_dry_run(to_delete)
    logging.info("Found %d items for removal.", len(to_delete))

    if not args.delete:
        print("\nDry-run mode ON. No files/folders were deleted.")
        logging.info("Dry-run mode. Listing only, nothing deleted.")
        logging.info("=== Cleanup scan finished ===")
        return

    if not to_delete:
        logging.info("No deletion required.")
        logging.info("=== Cleanup scan finished ===")
        return

    confirm = input("\nType 'YES' to delete all listed items: ").strip().upper()
    if confirm != "YES":
        print("Deletion cancelled by user.")
        logging.info("Deletion cancelled by user.")
        logging.info("=== Cleanup scan finished ===")
        return

    delete_items(to_delete)
    logging.info("Cleanup deletion complete.")
    logging.info("=== Cleanup scan finished ===")


if __name__ == "__main__":
    main()
