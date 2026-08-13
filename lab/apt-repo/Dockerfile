FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends dpkg-dev python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY build-repo.sh /usr/local/bin/build-repo.sh
RUN chmod 0755 /usr/local/bin/build-repo.sh \
    && /usr/local/bin/build-repo.sh

EXPOSE 8080
CMD ["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/srv/repo"]
