# Hardened container image (PT-8.4). Build: docker build -f deploy/Dockerfile -t webfilter-proxy .
# Run (config with proxy_auth is required when listening beyond loopback, D-13):
#   docker run --rm -p 127.0.0.1:8080:8080 -v $PWD/config:/etc/webfilter:ro -v wf-logs:/var/log/webfilter \
#     --read-only --cap-drop ALL --security-opt no-new-privileges webfilter-proxy
FROM rust:1.99.0-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bins

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin webfilter \
 && mkdir -p /var/log/webfilter /var/lib/webfilter && chown webfilter /var/log/webfilter /var/lib/webfilter
COPY --from=build /src/target/release/webfilter-proxy /usr/local/bin/
USER 10001
EXPOSE 8080
ENTRYPOINT ["webfilter-proxy", "--config", "/etc/webfilter/config.toml"]
CMD ["run"]
