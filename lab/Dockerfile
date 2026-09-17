# One image, parameterised by ROLE. Each role's seed script plants exactly the
# weaknesses named in scope.yaml — nothing hidden, nothing extra.
FROM debian:bookworm-slim

# The expensive layer comes FIRST and references no ARG, so all three images
# share one cached apt install. Declaring ARG ROLE above this would change the
# cache key per role and run apt three times.
#
# openssh-server : the lateral-movement surface (T1021.004)
# sudo           : the sudo misconfiguration surface (T1548.003)
# python3        : used by the collector probes over `docker exec`
# iproute2       : `ss` for the listening-ports probe
# tar            : the shell-escape binary in app01's sudo rule
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        python3 \
        iproute2 \
        procps \
        tar \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /etc/ascend

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Everything below this line is role-specific and is not shared between images.
ARG ROLE
ARG DECLARED_KERNEL="0.0.0"

# The simulated per-host kernel. Read by probes/kernel.py and always reported
# alongside the real `uname -r`, so the two can never be confused.
RUN echo "${DECLARED_KERNEL}" > /etc/ascend/declared_kernel

COPY seed/common.sh /tmp/seed/common.sh
COPY seed/${ROLE}.sh /tmp/seed/role.sh
COPY keys/ /tmp/keys/
COPY exploits/ /tmp/exploits/

RUN bash /tmp/seed/role.sh && rm -rf /tmp/seed /tmp/keys /tmp/exploits

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
