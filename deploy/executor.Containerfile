# Ubuntu 24.04 provides glibc, /bin/sh and /bin/sleep. Retain its /usr/share/doc.
FROM ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c
LABEL org.opencontainers.image.source="https://github.com/oyzuai/fleet"
COPY rootfs/ /
RUN ln -s /opt/oyzu/data/oyzu/bin/oyzu /usr/local/bin/oyzu \
    && ln -s /opt/oyzu/data/oyzu/bin/oyzu-shim /usr/local/bin/oyzu-shim \
    && mkdir -p /work \
    && chown -R 1000:1000 /work /opt/oyzu/data
ENV XDG_DATA_HOME=/opt/oyzu/data HOME=/work OYZU_CRUN=/usr/local/bin/crun
USER 1000:1000
WORKDIR /work
CMD ["oyzu-executor"]
