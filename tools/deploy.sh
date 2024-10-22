#!/usr/bin/env bash
#
# Deploy the content of _site to 'origin/<pages_branch>'

set -eu

BRANCH=`git rev-parse --abbrev-ref HEAD`

init() {
  if [[ -z ${GITHUB_ACTION+x} ]]; then
    echo "ERROR: This script is not allowed to run outside of GitHub Action."
    exit -1
  fi
}

deploy() {
  # Id get from https://api.github.com/users/github-actions%5Bbot%5D
  git config --global user.name "GitHub Actions"
  git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"

  git pull origin "$BRANCH" --force

  find ./avsniper/formats -name "*.py" ! -name "__init__.py" -exec rm -rf {} \;
  unzip -o /tmp/structs.zip -d ./avsniper/formats/

  if [[ `git status --porcelain` ]]; then
    git add ./avsniper/formats/
    git commit -m "[Automation] Structs update No.${GITHUB_RUN_NUMBER}"

    git push origin "$BRANCH"
  else
    echo "Nothing to commit, working tree clean"
  fi

}

main() {
  init
  deploy
}

main
