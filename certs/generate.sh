# Check if out directory exists
if [ -d "out" ]; then
    # Remove out directory
    rm -rf out
fi

# Create out directory
mkdir -p out

# Generate localhost.pem and localhost.key
openssl req -x509 -out out/cert.pem -keyout out/cert.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=localhost" -extensions EXT -config cert.conf