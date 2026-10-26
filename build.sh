#!/usr/bin/env sh
set -eu
if ! command -v java >/dev/null 2>&1; then
  echo 'Erro: instale JDK 25.' >&2
  exit 1
fi
JAVA_VERSION=$(java -version 2>&1 | sed -n '1s/.*version "\([0-9][0-9]*\).*/\1/p')
if [ -z "$JAVA_VERSION" ] || [ "$JAVA_VERSION" -lt 25 ]; then
  echo "Erro: Paper 26.3 exige JDK 25+ para compilar; encontrado Java ${JAVA_VERSION:-desconhecido}." >&2
  exit 1
fi
if ! command -v gradle >/dev/null 2>&1; then
  echo 'Erro: Gradle não encontrado.' >&2
  exit 1
fi
exec gradle --no-daemon clean build
