# Start with a Go image as the base
FROM golang:1.16-alpine AS build

# Set environment variables for the app
ENV PORT=8087 \
    LOG_LEVEL=info \
    HTTP_PROXY= \
    HTTPS_PROXY=

# Copy the app source code to the container
COPY . /app

# Compile the app
RUN cd /app/scan && go build -o /bin/app

# Create a new image with just the compiled binary and necessary libraries
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=build /bin/app /bin/app

# Set environment variables for the app in the new image
ENV PORT=${PORT} \
    LOG_LEVEL=${LOG_LEVEL} \
    HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY}

# Start the app on the specified port
CMD /bin/app
