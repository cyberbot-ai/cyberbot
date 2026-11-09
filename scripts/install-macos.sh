#!/bin/bash
set -euo pipefail

# Functions keep OS integration separate from filesystem installation so tests
# can use disposable bundles and replace only process/search/privilege probes.
install_platform() { /usr/bin/uname -s; }
install_processes() { /usr/bin/pgrep -x cyberbot; }
install_copy() { /usr/bin/ditto --rsrc --extattr "$1" "$2"; }
install_move() { /bin/mv "$1" "$2"; }
install_register() {
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$1"
}
install_import() { /usr/bin/mdimport -i "$1"; }
install_find() { /usr/bin/mdfind -onlyin "$1" "kMDItemCFBundleIdentifier == 'dev.cyberbot.desktop'"; }
install_wait() { /bin/sleep 1; }
install_uid() { /usr/bin/id -u; }
install_signature() { /usr/bin/codesign --verify --deep --strict "$1"; }
install_admin_needed() {
  [[ ! -w "$1" || ( -e "$1/Cyberbot.app" && ! -w "$1/Cyberbot.app/Contents" ) ]]
}
install_privileged_copy() {
  /usr/bin/sudo /bin/bash "$INSTALL_SCRIPT" copy "$1" "$2"
}

install_error() { printf 'Installation error: %s\n' "$*" >&2; }

install_check_running() {
  local result
  if install_processes >/dev/null; then
    install_error 'Cyberbot is already running. Quit it from the menu, then run make install again. Closing the window leaves the monitoring running.'
    return 1
  else
    result=$?
    if [[ "$result" -ne 1 ]]; then
      install_error 'Could not verify whether Cyberbot is running. Installation stopped.'
      return 1
    fi
  fi
}

install_check_platform() {
  if [[ "$(install_platform)" != Darwin ]]; then
    install_error 'make install is supported only on macOS.'
    return 1
  fi
}

install_preflight() {
  local uid
  install_check_platform || return 1
  uid=$(install_uid) || { install_error 'Unable to identify the user of the installation.'; return 1; }
  if [[ "$uid" == 0 ]]; then
    install_error 'Run make install without sudo. Administrator rights will only be requested for copying if needed.'
    return 1
  fi
  install_check_running
}

install_validate_bundle() {
  local bundle=$1 existing=${2:-} identifier executable package
  if [[ -L "$bundle" || ! -d "$bundle" || ! -f "$bundle/Contents/Info.plist" || -L "$bundle/Contents/Info.plist" ]]; then
    install_error "No valid app bundle found: $bundle"
    return 1
  fi
  identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$bundle/Contents/Info.plist" 2>/dev/null) || identifier=''
  executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$bundle/Contents/Info.plist" 2>/dev/null) || executable=''
  package=$(/usr/libexec/PlistBuddy -c 'Print :CFBundlePackageType' "$bundle/Contents/Info.plist" 2>/dev/null) || package=''
  if [[ "$identifier" != dev.cyberbot.desktop || "$executable" != cyberbot || "$package" != APPL || ! -f "$bundle/Contents/MacOS/cyberbot" || ! -x "$bundle/Contents/MacOS/cyberbot" || -L "$bundle/Contents/MacOS/cyberbot" ]]; then
    install_error "Invalid Cyberbot app bundle (identifier, Info.plist or executable file): $bundle"
    return 1
  fi
  if [[ "$existing" != existing ]] && ! install_signature "$bundle"; then
    install_error "Invalid app signature: $bundle"
    return 1
  fi
}

install_validate_destination() {
  local destination=$1
  if [[ -L "$destination" ]]; then
    install_error "I’m not replacing a symbolic link: $destination"
    return 1
  fi
  if [[ -e "$destination" ]]; then
    install_validate_bundle "$destination" existing || return 1
  fi
}

install_copy_bundle() (
  # The lock and staging directory live on the destination filesystem. Never
  # merge an old bundle with new files, and never delete an unknown destination.
  local source=$1 parent=$2 destination lock staging='' committed=0
  install_check_platform || return 1
  install_check_running || return 1
  install_validate_bundle "$source" || return 1
  if [[ "$source" != /* || "$parent" != /* || ! -d "$parent" || "$source" == *$'\n'* || "$parent" == *$'\n'* ]]; then
    install_error 'Absolute paths to the bundle and the existing program folder are needed.'
    return 1
  fi
  source=$(cd "$source" && pwd -P) || return 1
  parent=$(cd "$parent" && pwd -P) || return 1
  destination="$parent/Cyberbot.app"
  if [[ "$source" == "$destination" ]]; then
    install_error 'Original and installed copies of the application are the same.'
    return 1
  fi
  install_validate_destination "$destination" || return 1
  lock="$parent/.cyberbot-install.lock"
  if ! /bin/mkdir "$lock"; then
    install_error "The installation folder is busy: $if the previous installation was interrupted, check and delete the remaining empty lock directory."
    return 1
  fi
  cleanup() {
    local result=$? keep=0
    trap - EXIT INT TERM HUP
    if [[ -n "$staging" && -e "$staging/previous.app" && "$committed" == 0 ]]; then
      if [[ ! -e "$destination" && ! -L "$destination" ]] && install_move "$staging/previous.app" "$destination"; then
        printf 'Previous version of Cyberbot restored.\n' >&2
      else
        install_error "We couldn’t restore the previous version. It’s saved here: $staging/previous.app"
        keep=1
        result=1
      fi
    fi
    if [[ -n "$staging" && "$keep" == 0 ]]; then
      if ! /bin/rm -rf "$staging"; then
        install_error "Failed to delete the temporary catalog: $staging"
        result=1
      fi
    fi
    /bin/rmdir "$lock" || result=1
    exit "$result"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  staging=$(/usr/bin/mktemp -d "$parent/.cyberbot-install.XXXXXX") || return 1
  install_copy "$source" "$staging/new.app" || return 1
  install_validate_bundle "$staging/new.app" || return 1
  # A user could have opened Cyberbot or changed the destination during copying.
  install_check_running || return 1
  install_validate_destination "$destination" || return 1
  if [[ -e "$destination" ]]; then
    install_move "$destination" "$staging/previous.app" || return 1
  fi
  install_move "$staging/new.app" "$destination" || return 1
  committed=1
)

install_spotlight() {
  local destination=$1 parent=$2 deadline matches match
  if ! install_register "$destination"; then
    install_error "App installed in $destination, but registration in macOS failed."
    return 1
  fi
  if ! install_import "$destination"; then
    install_error "App installed in $destination, but the Spotlight indexing request failed."
    return 1
  fi
  deadline=$((SECONDS + 30))
  while :; do
    if ! matches=$(install_find "$parent"); then
      install_error "App installed in $destination, but the Spotlight check failed."
      return 1
    fi
    while IFS= read -r match; do
      if [[ "$match" == "$destination" || "$match" -ef "$destination" ]]; then
        printf 'Spotlight: Cyberbot found. Press Command-Space and type Cyberbot.\n'
        return 0
      fi
    done <<< "$matches"
    if (( SECONDS >= deadline )); then break; fi
    install_wait
  done
  printf 'The app is installed; Spotlight is still being updated. If Cyberbot doesn’t show up, check if the app is allowed and if the folder isn’t excluded “Programme programmes” indexed.\n'
}

install_main() {
  local action=${1:-} source=${2:-} parent=${3:-/Applications}
  case "$action" in
    check) install_preflight && install_validate_destination "$parent/Cyberbot.app" ;;
    copy) install_copy_bundle "$source" "$parent" ;;
    install)
      install_preflight || return 1
      install_validate_bundle "$source" || return 1
      if [[ "$parent" != /* || ! -d "$parent" ]]; then
        install_error 'The program folder must exist and have an absolute path.'
        return 1
      fi
      parent=$(cd "$parent" && pwd -P) || return 1
      install_validate_destination "$parent/Cyberbot.app" || return 1
      if install_admin_needed "$parent"; then
        printf 'For copying in %s needs administrator rights.\n' "$parent"
        install_privileged_copy "$source" "$parent" || return 1
      else
        install_copy_bundle "$source" "$parent" || return 1
      fi
      printf 'Installed: %s/Cyberbot.app\n' "$parent"
      install_spotlight "$parent/Cyberbot.app" "$parent"
      ;;
    *) install_error 'Use make install install (or check/install/copy to call the script).'; return 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  INSTALL_SCRIPT=$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")
  install_main "$@"
fi
