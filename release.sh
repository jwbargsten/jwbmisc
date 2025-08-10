#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset


TAG=$1

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid version format"
fi

confirm() {
  # https://stackoverflow.com/questions/1885525/how-do-i-prompt-a-user-for-confirmation-in-bash-script
  read -p "${1:-Are you sure?} (y/n) " -n 1 -r
  echo    # (optional) move to a new line
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    return 0
  fi
  return 1
}

confirm_or_exit() {
  if ! confirm "$@"; then
    exit 0
  fi
}

confirm_or_exit "Tag release $TAG?"

git tag "$TAG"
make build
confirm_or_exit "Publish?"
make publish
git push --tags

# if you ever need to delete a tag: git tag -d v0.0.1
