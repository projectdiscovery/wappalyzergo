# Build the Go project
FROM golang:1.21 as builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main ./cmd/update-fingerprints

# Create a minimal image
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/main .

ENTRYPOINT ["./main"]
