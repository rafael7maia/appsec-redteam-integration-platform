#!/bin/bash

echo "🛑 Stopping All AppSec Services"
echo "==============================="

# Stop main environment
echo "🔧 Stopping main environment..."
docker-compose down
echo "✅ Main environment stopped"

# Stop DefectDojo
echo "🛡️ Stopping DefectDojo..."
cd defectdojo
docker-compose down
echo "✅ DefectDojo stopped"
cd ..

# Stop Dependency Track
echo "📊 Stopping Dependency Track..."
cd dependencytrack
docker-compose down
echo "✅ Dependency Track stopped"
cd ..

# Clean up any remaining containers
echo "🧹 Cleaning up..."
docker system prune -f > /dev/null 2>&1

echo "✅ All services stopped successfully!"
echo "💡 To start again: ./start_services.sh"