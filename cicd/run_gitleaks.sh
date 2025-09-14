#!/bin/bash

echo "🔍 Running GitLeaks Secret Scan..."

# Create results directory
mkdir -p results

# Run GitLeaks scan
docker run --rm \
  -v $(pwd)/codigo:/code:ro \
  -v $(pwd)/results:/results \
  zricethezav/gitleaks:latest \
  detect --source /code --report-format json --report-path /results/gitleaks-report.json --verbose

echo "✅ GitLeaks scan completed!"
echo "📊 Results saved to: results/gitleaks-report.json"

# Show summary
if [ -f "results/gitleaks-report.json" ]; then
    echo "🚨 Secrets found:"
    cat results/gitleaks-report.json | jq -r '.[] | "- \(.RuleID): \(.File):\(.StartLine)"' 2>/dev/null || echo "No secrets detected or jq not available"
else
    echo "ℹ️ No secrets detected or scan failed"
fi