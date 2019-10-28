FROM debian:sid

FROM jess/chromium

USER root
RUN apt-get update -yq && \
    apt-get install -yq ca-certificates sudo xsel
RUN mkdir -p /usr/share/ca-certificates/extra

ENV PROXY_SERVER=http://host.docker.internal:8080

USER chromium
ENTRYPOINT [ "chromium" ]
CMD [ "--no-sandbox" "--proxy-server=${PROXY_SERVER}" ]
