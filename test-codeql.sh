#!/bin/bash
# SPDX-FileCopyrightText: 2025 Swiss Confederation
# SPDX-License-Identifier: MIT

# CodeQL Advanced Mode Test Script

# To run the sript extract codeql-bundle-linux64.tar.gz to /codeql folder
# Download bundle here: https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz

set -e

echo "🔍 Testing CodeQL Advanced Mode Configuration..."

# Pfade
CODEQL_HOME="./codeql"
DB_NAME="swiyu-application-test-codeql-db"

# Cleanup existing database and results
echo "🧹 Cleaning up existing database and results..."
rm -rf $DB_NAME codeql-results.sarif

# Stelle sicher, dass das Projekt gebaut ist
echo "📦 Building project with Maven..."
mvn clean compile -q

# Erstelle CodeQL Database (ohne config - wird erst beim analyze benötigt)
echo "🗄️  Creating CodeQL database..."
$CODEQL_HOME/codeql database create $DB_NAME \
  --language=java \
  --source-root=. \
  --overwrite \
  --command="mvn compile -q"

# Führe Analyse durch (hier wird die config verwendet)
echo "🔎 Running CodeQL analysis..."
$CODEQL_HOME/codeql database analyze $DB_NAME \
  --format=sarif-latest \
  --output=codeql-results.sarif \
  --sarif-category="/language:java" \
  java-security-extended java-security-and-quality


# Zeige Zusammenfassung
echo "📊 Analysis complete! Results saved to codeql-results.sarif"
echo "📁 Database created in $DB_NAME"

# Optional: Zeige Anzahl der Findings
if [ -f "codeql-results.sarif" ]; then
    findings=$(grep -o '"ruleId"' codeql-results.sarif | wc -l)
    echo "🔍 Found $findings security/quality issues"
fi

# Cleanup-Option
echo ""
echo "To clean up, run: rm -rf $DB_NAME codeql-results.sarif"