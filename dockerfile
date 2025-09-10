# Use official Go image as builder
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Copy go.mod and go.sum first for caching
COPY go.mod ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary
RUN go build -o reverse-proxy main.go

# Use a minimal image for runtime
FROM alpine:latest

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/reverse-proxy .

# Copy SSL certificates if needed (optional)
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

# Set environment variables (can override with docker-compose)
ENV PORT=80

EXPOSE 80

CMD ["./reverse-proxy"]
