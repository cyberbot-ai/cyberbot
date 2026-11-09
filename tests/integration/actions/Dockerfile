ARG BASE_IMAGE=cyberbot-ssh-test:local
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends nginx && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /actions-entrypoint.sh
ENTRYPOINT ["/bin/sh","/actions-entrypoint.sh"]
