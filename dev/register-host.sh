#!/bin/sh
# Registers a development build as the native messaging host of the unpacked
# extension, for the current user only. Managed machines get a machine-wide
# manifest instead; see docs/enterprise.md.
#
#   dev/register-host.sh <binary> chrome|firefox|<Chrome --user-data-dir>
set -eu

[ $# -eq 2 ] || { echo "usage: $0 <binary> chrome|firefox|<Chrome --user-data-dir>" >&2; exit 2; }
case $1 in
/*) bin=$1 ;;
*) bin=$PWD/$1 ;;
esac
support="$HOME/Library/Application Support"
allowed='"allowed_origins": ["chrome-extension://ljanpcedhfnidohflcgdjflhhjebpikb/"]'
case $2 in
chrome) dir="$support/Google/Chrome" ;;
firefox)
  dir="$support/Mozilla"
  allowed='"allowed_extensions": ["saml2sts@yokonao.github.io"]'
  ;;
*) dir=$2 ;;
esac

mkdir -p "$dir/NativeMessagingHosts"
file="$dir/NativeMessagingHosts/io.github.yokonao.saml2sts.json"
cat > "$file" <<JSON
{
  "name": "io.github.yokonao.saml2sts",
  "description": "saml2sts",
  "path": "$bin",
  "type": "stdio",
  $allowed
}
JSON
echo "wrote $file"
