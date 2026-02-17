#!/usr/bin/env python3
"""
Smart Downloads Organizer

Automatically categorizes and organizes files by type.
Generates JSON and human-readable text reports.

Features:
- Uses pathlib for all file operations
- Categorizes files by extension
- Handles edge cases (no extension, uppercase, multiple dots)
- Creates category folders if missing
- Safely moves files with error handling
- Generates JSON + text reports with statistics
- Accepts directory path as command-line argument
"""

from pathlib import Path
import shutil
import json
from datetime import datetime
import sys


# -----------------------------
# Category mappings
# -----------------------------
CATEGORIES = {
    "documents": ["pdf", "doc", "docx", "txt", "rtf", "odt"],
    "images": ["jpg", "jpeg", "png", "gif", "bmp", "svg"],
    "archives": ["zip", "tar", "gz", "rar", "7z"],
    "executables": ["exe", "msi", "bat", "sh"],
    "videos": ["mp4", "avi", "mkv", "mov"],
    "audio": ["mp3", "wav", "flac", "aac"]
}


# -----------------------------
# Helper Functions
# -----------------------------
def get_extension(filename: Path) -> str:
    """
    Extract and normalize file extension.

    Handles:
    - No extension
    - Uppercase extensions
    - Multiple dots (e.g. backup.tar.gz)
    """
    if not filename.suffix:
        return ""

    # Handle multi-part extensions like .tar.gz
    suffixes = [s.lower().lstrip(".") for s in filename.suffixes]

    if len(suffixes) >= 2:
        return ".".join(suffixes[-2:])

    return suffixes[-1]


def categorize_file(filename: Path) -> str:
    """
    Determine file category based on extension.
    Defaults to 'other' if no match is found.
    """
    extension = get_extension(filename)

    for category, extensions in CATEGORIES.items():
        if extension in extensions or any(extension.endswith(ext) for ext in extensions):
            return category

    return "other"


# -----------------------------
# Core Logic
# -----------------------------
def organize_directory(source_dir: Path) -> dict:
    """
    Main organization logic.
    Walks the directory, categorizes files, and moves them safely.
    Returns statistics dictionary.
    """
    stats = {
        "total_files": 0,
        "moved_files": 0,
        "errors": 0,
        "categories": {category: 0 for category in CATEGORIES},
        "other": 0
    }

    for item in source_dir.iterdir():
        # Skip directories and report files
        if item.is_dir() or item.name.startswith("organization_report"):
            continue

        stats["total_files"] += 1
        category = categorize_file(item)

        target_dir = source_dir / category
        target_dir.mkdir(exist_ok=True)

        target_path = target_dir / item.name

        try:
            # Avoid overwriting existing files
            if target_path.exists():
                target_path = target_dir / f"{item.stem}_copy{item.suffix}"

            shutil.move(str(item), str(target_path))
            stats["moved_files"] += 1

            if category in stats["categories"]:
                stats["categories"][category] += 1
            else:
                stats["other"] += 1

        except Exception as e:
            print(f"Error moving {item.name}: {e}")
            stats["errors"] += 1

    return stats


# -----------------------------
# Reporting
# -----------------------------
def generate_json_report(stats: dict, source_dir: Path) -> None:
    """
    Generate JSON report with timestamp and statistics.
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "directory": str(source_dir.resolve()),
        "statistics": stats
    }

    report_path = source_dir / "organization_report.json"
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


def generate_text_report(stats: dict, source_dir: Path) -> None:
    """
    Generate human-readable text report.
    """
    lines = [
        "Smart Downloads Organizer Report",
        "=" * 35,
        f"Directory: {source_dir.resolve()}",
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Total files processed: {stats['total_files']}",
        f"Files successfully moved: {stats['moved_files']}",
        f"Errors encountered: {stats['errors']}",
        "",
        "Files by category:"
    ]

    for category, count in stats["categories"].items():
        lines.append(f"  - {category.capitalize()}: {count}")

    lines.append(f"  - Other: {stats['other']}")

    report_path = source_dir / "organization_report.txt"
    with report_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# -----------------------------
# Entry Point
# -----------------------------
def main():
    """
    Program entry point.
    Accepts directory path as a command-line argument.
    """
    source_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("downloads")

    print(f"Organizing files in: {source_dir}")

    if not source_dir.exists() or not source_dir.is_dir():
        print(f"Fatal error: Directory does not exist: {source_dir}")
        sys.exit(1)

    stats = organize_directory(source_dir)
    generate_json_report(stats, source_dir)
    generate_text_report(stats, source_dir)

    print("Organization complete!")
    print(f"Processed {stats['total_files']} files.")


if __name__ == "__main__":
    main()