ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}
ARG EXTRA_PACKAGES=""
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server python3 rsync procps systemd systemd-journal-remote ${EXTRA_PACKAGES} && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && useradd -m -s /bin/sh ops
RUN mkdir -p /home/ops/.ssh && chmod 700 /home/ops/.ssh && chown -R ops:ops /home/ops/.ssh
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
