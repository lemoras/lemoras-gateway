#!/bin/bash
set -e
-----------------

APP_NAME="reverse-proxy"
IMAGE_NAME="reverse-proxy-prod"
CONTAINER_NAME="reverse-proxy-prod"
ENV_FILE=".env"
PORT=${PORT:-8080}

# Check if .env exists
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Please create it with proper environment variables."
  exit 1
fi

# Build Docker image
echo "Building Docker image..."
docker build -t $IMAGE_NAME .

# Stop existing container if running
if [ "$(docker ps -q -f name=$CONTAINER_NAME)" ]; then
  echo "Stopping existing container..."
  docker stop $CONTAINER_NAME
  docker rm $CONTAINER_NAME
fi

# Run container
echo "Starting container..."
docker run -d \
  --name $CONTAINER_NAME \
  --env-file $ENV_FILE \
  -p $PORT:$PORT \
  --restart unless-stopped \
  $IMAGE_NAME

echo "✅ $APP_NAME deployed successfully on port $PORT"
