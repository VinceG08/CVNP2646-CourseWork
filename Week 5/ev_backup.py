# evidence_backup.py
# Create forensic-safe backups with metadata preservation

import shutil
from pathlib import Path
from datetime import datetime

print("=== Forensic Evidence Backup Tool ===\n")

# Create sample evidence file with specific timestamp
evidence_path = Path('evidence.log')
evidence_path.write_text("""2024-01-08 10:15:23 - Suspicios connection to 203.0.113.45
2024-01-08 10:16:45 - Port scan detected from external IP
2024-01-08 10:17:12 - Malware execution attempt logged
""")

print(f"Created evidence file: {evidence_path}")

# Get original metadata
original_stats = evidence_path.stat()
original_mtime = datetime.fromtimestamp(original_stats.st_mtime)

print(f"Original modifcation time: {original_mtime}\n")

# Create evidence backup directory
backup_dir = Path('evidence_backup')
backup_dir.mkdir(exist_ok=True)

# BAD WAY - Using copy (loses metadata)
bad_backup = backup_dir / 'evidence_copy_bad.log'
shutil.copy(evidence_path, bad_backup)

bad_stats = bad_backup.stat()
bad_mtime = datetime.fromtimestamp(bad_stats.st_mtime)

print("❌ BAD: Using shutil.copy()")
print(f"  Backup modifcation time: {bad_mtime}")
print(f"  Metadata LOST - timestamp shows backup time, not original!\n")

# GOOD WAY - Using copy2 (preserves metadata)
good_backup = backup_dir / 'evidence_copy_good.log'
shutil.copy2(evidence_path, good_backup)

good_stats = good_backup.stat()
good_mtime = datetime.fromtimestamp(good_stats.st_mtime)

print("✅ GOOD: Using shutil.copy2()")
print(f"  Backup modifaction time: {good_mtime}")
print(f"  Metadta PRESERVED - exact match to original!\n")

# Create timestamped archive of evidence
print("Createing forsenic archive...")

archive_name = f"evidence_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
archive_path = shutil.make_archive(archive_name, 'zip', backup_dir)

print(f"✓ Archive created: {Path(archive_path).name}")
print(f" Size: {Path(archive_path).stat().st_size} bytes")

# Move archive to secure storage
secure_storage = Path('secure_storage')
secure_storage.mkdir(exist_ok=True)

final_location = shutil.move(archive_path, secure_storage / Path(archive_path).name)

print(f"\n✓ Archive moved to secure storage:")
print(f"  {final_location}")

print("\n=== Backup Complete ===")
print("Evidence preserved with original timestamps")
print("Archive creatyed and moved to secure storage")