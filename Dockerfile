# Use golang:1.21 as the base image
FROM golang:1.21

# Copy the entire project directory into the container
COPY . /app

# Set the working directory to /app
WORKDIR /app

# Define the entrypoint to run the update-fingerprints command
ENTRYPOINT ["go", "run", "cmd/update-fingerprints/main.go"]
