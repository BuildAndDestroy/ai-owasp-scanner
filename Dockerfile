FROM golang:1.20 AS builder

# Set the working directory
WORKDIR /app

# Copy the source code
COPY . .

# Build for multiple architectures
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/owasp-scanner ./cmd/owasp-scanner/main.go \
    && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/owasp-scanner-arm ./cmd/owasp-scanner/main.go \
    && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/owasp-scanner.exe ./cmd/owasp-scanner/main.go \
    && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/owasp-scanner-darwin ./cmd/owasp-scanner/main.go

# Final stage
FROM scratch

# Copy binaries from builder
COPY --from=builder /app/bin/ /bin/

# Command to run the application
CMD ["/bin/owasp-scanner"]