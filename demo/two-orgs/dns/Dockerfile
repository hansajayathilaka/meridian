# demo/two-orgs/dns — a small internal DNS service so `federation.discovery = "srv"` resolves a
# REAL `_meridian-fed._tcp.<domain>` SRV record (task 2.11 deliverable 2), not a faked one. Only
# used by the SRV-mode compose override (docker-compose.srv.yml) — the static-map profile needs no
# DNS server at all (that's the whole point of the air-gap map, ADR 0002/apps/rendezvous/src/
# federation/discovery.rs).
FROM alpine:3
RUN apk add --no-cache dnsmasq
COPY dnsmasq.conf /etc/dnsmasq.conf
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["dnsmasq", "-k", "--log-facility=-"]
