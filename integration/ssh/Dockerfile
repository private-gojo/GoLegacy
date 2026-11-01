FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server dropbear \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/sh tunnel \
    && echo 'tunnel:test-only-password' | chpasswd \
    && mkdir -p /run/sshd /etc/dropbear \
    && ssh-keygen -A

RUN printf '%s\n' \
    'PasswordAuthentication yes' \
    'KbdInteractiveAuthentication no' \
    'UsePAM no' \
    'PermitRootLogin no' \
    'AllowUsers tunnel' >> /etc/ssh/sshd_config

EXPOSE 22 2223

CMD ["/bin/sh", "-c", "/usr/sbin/sshd -D -e & exec /usr/sbin/dropbear -F -E -p 2223"]
