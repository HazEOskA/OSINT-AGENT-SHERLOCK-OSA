FROM alpine:3.22

RUN apk add --no-cache tor tini \
    && mkdir -p /var/lib/tor \
    && chown -R tor:tor /var/lib/tor

COPY --chown=tor:tor docker/torrc /etc/tor/torrc
USER tor
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["tor", "-f", "/etc/tor/torrc"]
