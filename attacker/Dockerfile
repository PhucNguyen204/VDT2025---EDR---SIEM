FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y hydra openssh-client netcat-openbsd curl wget && \
    rm -rf /var/lib/apt/lists/*

# Create wordlists directory
RUN mkdir -p /usr/share/wordlists

# Copy attack scripts and wordlists
COPY attack_scripts.sh /usr/local/bin/attack_scripts.sh
COPY passwords.txt /usr/share/wordlists/passwords.txt

# Make script executable
RUN chmod +x /usr/local/bin/attack_scripts.sh

# Set working directory
WORKDIR /root

# Default command - run attack scripts
CMD ["/usr/local/bin/attack_scripts.sh"]