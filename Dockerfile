FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy source code
COPY mikan_alist_uploader.go .

# Download dependencies and build
RUN go mod init mikan_alist_uploader && \
    go build -o /app/mikan_alist_uploader

# Create a minimal runtime image
FROM alpine:3.18

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/mikan_alist_uploader .

# Create directory for persistent data
RUN mkdir -p /app/data

# Set the data directory as a volume
VOLUME /app/data

ENTRYPOINT ["/app/mikan_alist_uploader"] 