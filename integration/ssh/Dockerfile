FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates openssh-server dropbear build-essential cmake git python3 \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/ambrop72/badvpn.git /opt/badvpn \
    && cmake -S /opt/badvpn -B /opt/badvpn/build -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 \
    && cmake --build /opt/badvpn/build --target badvpn-udpgw -j2 \
    && install -m 0755 /opt/badvpn/build/udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw

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

CMD ["/bin/sh", "-c", "/usr/sbin/sshd -D -e & /usr/sbin/dropbear -F -E -p 2223 & /usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --loglevel info & exec python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((\"127.0.0.1\",9999)); exec(\"while True:\\n d,a=s.recvfrom(65535)\\n s.sendto(d,a)\")'"]
