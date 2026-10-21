#!/usr/bin/env bash
# Recrée main (et dev) avec UN SEUL commit, identique au contenu de la référence source,
# sans aucun historique antérieur (donc sans lignes Co-Authored-By / Claude-Session).
#
# Usage :
#   ./scripts/recreate-clean-history.sh                 # source = dev, message par défaut
#   ./scripts/recreate-clean-history.sh dev "optiCOMBAT v1.0.0"
#   ./scripts/recreate-clean-history.sh dev "optiCOMBAT v1.0.0" --push   # pousse aussi (force)
#
# Sécurité : les anciennes têtes sont sauvegardées en tags locaux backup/<branche>-<date>
# (jamais poussés) ; le push utilise --force-with-lease.
set -euo pipefail

SRC="${1:-dev}"
MSG="${2:-optiCOMBAT v1.0.0}"
PUSH="${3:-}"

cd "$(git rev-parse --show-toplevel)"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Modifications non commitées : commit ou stash d'abord." >&2
  exit 1
fi
git rev-parse --verify --quiet "$SRC^{commit}" >/dev/null || { echo "Référence introuvable : $SRC" >&2; exit 1; }

case "$MSG" in
  *Co-Authored-By*|*co-authored-by*|*Claude-Session*) echo "Message refusé : contient une signature." >&2; exit 1;;
esac

STAMP="$(date +%Y%m%d-%H%M%S)"
git fetch origin --quiet || true

# 1. Sauvegarde locale des anciennes têtes.
for b in main dev; do
  if git rev-parse --verify --quiet "refs/heads/$b" >/dev/null; then
    git tag "backup/$b-$STAMP" "refs/heads/$b"
    echo "Sauvegarde : backup/$b-$STAMP -> $(git rev-parse --short "refs/heads/$b")"
  fi
done

# 2. Commit racine unique avec l'arbre exact de la source (fichiers suivis uniquement).
TREE="$(git rev-parse "$SRC^{tree}")"
NAME="$(git config user.name || git log -1 --format=%an "$SRC")"
EMAIL="$(git config user.email || git log -1 --format=%ae "$SRC")"
NEW="$(GIT_AUTHOR_NAME="$NAME" GIT_AUTHOR_EMAIL="$EMAIL" \
       GIT_COMMITTER_NAME="$NAME" GIT_COMMITTER_EMAIL="$EMAIL" \
       git commit-tree "$TREE" -m "$MSG")"

# 3. Vérifications : même contenu, aucun parent, aucune signature.
[ "$(git rev-parse "$NEW^{tree}")" = "$TREE" ] || { echo "Arbre différent !" >&2; exit 1; }
[ -z "$(git rev-list --parents -n1 "$NEW" | cut -s -d' ' -f2)" ] || { echo "Le commit a un parent !" >&2; exit 1; }
if git log -1 --format=%B "$NEW" | grep -qiE 'co-authored-by|claude-session'; then
  echo "Signature détectée dans le message !" >&2; exit 1
fi

# 4. main et dev pointent sur ce commit unique.
CUR="$(git symbolic-ref --short -q HEAD || echo '')"
for b in main dev; do
  if [ "$CUR" = "$b" ]; then
    git reset --hard --quiet "$NEW"
  else
    git branch -f "$b" "$NEW"
  fi
done
echo "Nouveau commit racine : $(git rev-parse --short "$NEW") \"$MSG\" (main et dev)"
git log --oneline -n 3 main

# 5. Push (optionnel).
if [ "$PUSH" = "--push" ]; then
  for b in main dev; do
    if git rev-parse --verify --quiet "refs/remotes/origin/$b" >/dev/null; then
      git push --force-with-lease="$b:$(git rev-parse "refs/remotes/origin/$b")" origin "$b"
    else
      git push origin "$b"
    fi
  done
else
  echo
  echo "Rien n'est poussé. Pour publier :"
  echo "  git push --force-with-lease origin main dev"
fi
