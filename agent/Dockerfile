FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Cài rsyslog, openssh-server, curl
RUN apt-get update && apt-get install -y \
    rsyslog openssh-server curl ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

# === Tải Vector (fallback to official image approach) ===
WORKDIR /tmp
RUN curl -L https://github.com/vectordotdev/vector/releases/download/v0.43.0/vector-0.43.0-x86_64-unknown-linux-musl.tar.gz -o vector.tar.gz \
    && tar -xzf vector.tar.gz \
    && ls -la \
    && find . -name "vector" -type f \
    && cp */bin/vector /usr/local/bin/vector 2>/dev/null || cp vector-*/bin/vector /usr/local/bin/vector || \
       (echo "Fallback: installing from package" && \
        curl -1sLf 'https://repositories.timber.io/public/vector/cfg/setup/bash.deb.sh' | bash && \
        apt-get update && apt-get install -y vector) \
    && chmod +x /usr/local/bin/vector \
    && rm -rf /tmp/*

# === SSH cấu hình cơ bản ===
RUN mkdir /var/run/sshd \
    && echo 'root:root' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# === rsyslog cấu hình forward sang Vector ===
RUN echo "auth.* @@127.0.0.1:5514" >> /etc/rsyslog.d/90-vector.conf

# === Vector config (syslog source + console sink) ===
RUN mkdir -p /etc/vector
COPY vector.toml /etc/vector/vector.toml

EXPOSE 22 514/udp

# === Setup systemd alternatives và entrypoint script ===
RUN mkdir -p /app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# === Entrypoint: chạy nhiều service với manual start ===
CMD ["/app/entrypoint.sh"]
