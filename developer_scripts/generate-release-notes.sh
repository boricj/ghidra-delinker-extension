#!/bin/bash

set -eEu -o pipefail
shopt -s extdebug

GIT_CHANGELOG_COMMAND_LINE_VERSION="1.104.1"
GIT_CHANGELOG_COMMAND_LINE_JAR="git-changelog-command-line-${GIT_CHANGELOG_COMMAND_LINE_VERSION}.jar"

if [ ! -e "developer_scripts/${GIT_CHANGELOG_COMMAND_LINE_JAR}" ]
then
	wget "https://repo1.maven.org/maven2/se/bjurr/gitchangelog/git-changelog-command-line/${GIT_CHANGELOG_COMMAND_LINE_VERSION}/${GIT_CHANGELOG_COMMAND_LINE_JAR}" -O "developer_scripts/${GIT_CHANGELOG_COMMAND_LINE_JAR}"
fi

CURRENT_TAG=$(git describe --tags HEAD)
PREVIOUS_TAG=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)

if [ -z "${PREVIOUS_TAG}" ]
then
	echo >&2 "Generating release notes for ${CURRENT_TAG} from beginning..."
	java -jar "developer_scripts/${GIT_CHANGELOG_COMMAND_LINE_JAR}" --github-enabled --template developer_scripts/release-notes.mustache -std
else
	echo >&2 "Generating release notes for ${CURRENT_TAG} from ${PREVIOUS_TAG}..."
	java -jar "developer_scripts/${GIT_CHANGELOG_COMMAND_LINE_JAR}" --github-enabled --template developer_scripts/release-notes.mustache -std --from-revision "${PREVIOUS_TAG}"
fi
