# Ubuntu 24.04 provides glibc, /bin/sh and /bin/sleep. Retain its /usr/share/doc.
FROM ubuntu:24.04@sha256:24737cef17f4e22b1977df7d9a05e77c4e28b7da5b8911f8d8ccda136bf3573c
LABEL org.opencontainers.image.source="https://github.com/oyzuai/fleet"
COPY rootfs/ /
COPY --from=oyzu-fetch-oyzu oyzu-linux-x86_64 /opt/oyzu/data/oyzu/bin/oyzu
COPY --from=oyzu-fetch-oyzu-shim oyzu-shim-linux-x86_64 /opt/oyzu/data/oyzu/bin/oyzu-shim
COPY --from=oyzu-fetch-oyzu-notices oyzu-notices-linux-x86_64.txt /usr/share/doc/oyzu-pool-executor/oyzu-notices.txt
COPY --from=oyzu-fetch-crun / /var/tmp/crun/
COPY --from=oyzu-fetch-crun-source / /usr/share/doc/crun/source-archive/
COPY --from=oyzu-fetch-ca-certificates / /var/tmp/ca-deb/
# The materialized, versioned executor is the only executor-* file here.
# Preserve its bytes while installing it under the runtime command's name.
RUN mv /usr/local/bin/executor-* /usr/local/bin/oyzu-executor \
    && install -m755 /var/tmp/crun/* /usr/local/bin/crun \
    && chmod 755 /opt/oyzu/data/oyzu/bin/oyzu /opt/oyzu/data/oyzu/bin/oyzu-shim /usr/local/bin/crun \
    && dpkg-deb -x /var/tmp/ca-deb/*.deb /var/tmp/ca \
    && mkdir -p /etc/ssl/certs \
    && cat /var/tmp/ca/usr/share/ca-certificates/mozilla/*.crt > /etc/ssl/certs/ca-certificates.crt \
    && cp -R /var/tmp/ca/usr/share/doc/ca-certificates /usr/share/doc/ \
    && rm -rf /var/tmp/crun /var/tmp/ca /var/tmp/ca-deb \
    && tar -xOf /usr/share/doc/crun/source-archive/*.tar.gz --wildcards '*/COPYING' > /usr/share/doc/crun/COPYING \
    && tar -xOf /usr/share/doc/crun/source-archive/*.tar.gz --wildcards '*/COPYING.libcrun' > /usr/share/doc/crun/COPYING.libcrun \
    && ln -s /opt/oyzu/data/oyzu/bin/oyzu /usr/local/bin/oyzu \
    && ln -s /opt/oyzu/data/oyzu/bin/oyzu-shim /usr/local/bin/oyzu-shim \
    && mkdir -p /work \
    && chown -R 1000:1000 /work /opt/oyzu/data
ENV XDG_DATA_HOME=/opt/oyzu/data HOME=/work OYZU_CRUN=/usr/local/bin/crun
USER 1000:1000
WORKDIR /work
CMD ["oyzu-executor"]
