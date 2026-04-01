#!/bin/bash
echo "# Complete Codebase" > COMPLETE_CODE_README.md
find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.jsx" -o -name "*.html" -o -name "*.css" -o -name "Dockerfile*" -o -name "*.yml" -o -name "*.yaml" -o -name "*.toml" -o -name "*.sql" -o -name "*.sh" -o -name "*.json" -o -name "*.md" \) \
-not -path "*/node_modules/*" \
-not -path "*/.venv/*" \
-not -path "*/venv/*" \
-not -path "*/env/*" \
-not -path "*/__pycache__/*" \
-not -path "*/.git/*" \
-not -path "*/dist/*" \
-not -path "*/build/*" \
-not -path "*/.vscode/*" \
-not -name "package-lock.json" \
-not -name "COMPLETE_CODE_README.md" \
| sort | while read -r file; do
    echo "" >> COMPLETE_CODE_README.md
    echo "<!-- $file -->" >> COMPLETE_CODE_README.md
    echo "### ${file}" >> COMPLETE_CODE_README.md
    echo '```' >> COMPLETE_CODE_README.md
    cat "$file" >> COMPLETE_CODE_README.md
    echo '```' >> COMPLETE_CODE_README.md
done
