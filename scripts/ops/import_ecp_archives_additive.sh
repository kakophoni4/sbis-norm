#!/usr/bin/env bash
#
# Add key containers from a folder of ZIP/RAR archives to CryptoPro safely.
#
# This importer deliberately does NOT delete files, overwrite existing key
# directories, change the Certificate table, or call SBIS.  Each discovered
# keyset gets its own new HDIMAGE directory, so archives containing several
# signatures and files named "2560" cannot collide with one another.
#
# Run on the host:
#   cd /opt/sbis-norm
#   sudo bash scripts/ops/import_ecp_archives_additive.sh \
#     --source /root/new_ecp_stage_20260916 --batch 20260916 --apply
#
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/sbis-norm}"
CSP_ROOT="${CSP_ROOT:-/var/opt/cprocsp/keys/root}"
SOURCE_DIR=""
BATCH=""
APPLY=false

usage() {
  cat <<'EOF'
Usage:
  import_ecp_archives_additive.sh --source DIR --batch YYYYMMDD [--apply]

--source  Directory containing ZIP/RAR archives with CryptoPro keysets.
--batch   Safe ASCII batch label, e.g. 20260916.
--apply   Copy discovered keysets to CryptoPro. Without it only print a plan.

The importer never overwrites or removes existing files. It only creates:
  /var/opt/cprocsp/keys/root/new_<batch>_<archive>_<container>/
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE_DIR="$2"; shift 2 ;;
    --batch) BATCH="$2"; shift 2 ;;
    --apply) APPLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -n "$SOURCE_DIR" && -d "$SOURCE_DIR" ]] || { echo "--source must be an existing directory." >&2; exit 2; }
[[ "$BATCH" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "--batch may contain only A-Z, a-z, 0-9, _ and -." >&2; exit 2; }
mkdir -p "$CSP_ROOT"

command -v unzip >/dev/null || { echo "unzip is required." >&2; exit 1; }
if ! command -v unrar >/dev/null && ! command -v unar >/dev/null; then
  echo "unrar or unar is required for RAR files." >&2
  exit 1
fi

WORK_DIR="$SOURCE_DIR/.import_${BATCH}"
mkdir -p "$WORK_DIR"
MANIFEST="$WORK_DIR/manifest.tsv"
printf 'archive\tkeyset_source\tcrypto_destination\tkey_files\n' > "$MANIFEST"

extract_archive() {
  local archive="$1" destination="$2"
  case "${archive,,}" in
    *.zip)
      unzip -oq "$archive" -d "$destination"
      ;;
    *.rar)
      if command -v unrar >/dev/null; then
        unrar x -o+ "$archive" "$destination/" >/dev/null
      else
        unar -f -o "$destination" "$archive" >/dev/null
      fi
      ;;
    *) return 1 ;;
  esac
}

mapfile -d '' archives < <(
  find "$SOURCE_DIR" -maxdepth 1 -type f \( -iname '*.zip' -o -iname '*.rar' \) -print0 | sort -z
)

[[ ${#archives[@]} -gt 0 ]] || { echo "No ZIP/RAR archives found in $SOURCE_DIR" >&2; exit 1; }

echo "Source archives: ${#archives[@]}"
echo "Mode: $([[ "$APPLY" == true ]] && echo APPLY || echo PLAN)"
echo "CryptoPro root: $CSP_ROOT"

archive_index=0
keyset_total=0
for archive in "${archives[@]}"; do
  archive_index=$((archive_index + 1))
  unpack_dir="$WORK_DIR/unpacked_$(printf '%03d' "$archive_index")"
  mkdir -p "$unpack_dir"
  extract_archive "$archive" "$unpack_dir" || {
    echo "WARN: cannot extract: $archive" >&2
    continue
  }

  container_index=0
  while IFS= read -r -d '' keyset_dir; do
    key_count="$(find "$keyset_dir" -maxdepth 1 -type f -iname '*.key' -printf x | wc -c | tr -d ' ')"
    if (( key_count < 4 )); then
      echo "WARN: skip incomplete keyset ($key_count key files): $keyset_dir" >&2
      continue
    fi

    container_index=$((container_index + 1))
    keyset_total=$((keyset_total + 1))
    destination="$CSP_ROOT/new_${BATCH}_$(printf '%03d' "$archive_index")_$(printf '%02d' "$container_index")"

    printf '%s\t%s\t%s\t%s\n' "$archive" "$keyset_dir" "$destination" "$key_count" >> "$MANIFEST"
    echo "[$keyset_total] $(basename "$archive") -> $(basename "$destination") ($key_count .key)"

    if [[ "$APPLY" == true ]]; then
      if [[ -e "$destination" ]]; then
        echo "ERROR: destination already exists; refusing to overwrite: $destination" >&2
        exit 1
      fi
      mkdir -p "$destination"
      cp -a "$keyset_dir"/. "$destination"/
    fi
  done < <(find "$unpack_dir" -type f -iname 'header.key' -printf '%h\0' | sort -zu)
done

echo ""
echo "Keysets discovered: $keyset_total"
echo "Manifest: $MANIFEST"
if [[ "$APPLY" != true ]]; then
  echo "No CryptoPro files were changed. Re-run with --apply to copy keysets."
  exit 0
fi

echo ""
echo "New key directories created. Next, from $PROJECT_DIR run:"
echo "  docker compose restart web"
echo "  docker compose exec -T web python manage.py scan_certificates --install-uMy --quiet"
echo ""
echo "Do NOT use scan_certificates --clear for an additive import."
