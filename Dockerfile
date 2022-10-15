FROM alpine:3.16.2

RUN apk --no-cache add ca-certificates

RUN addgroup -g 1000 -S hoardix && \
    adduser -u 1000 -S hoardix -G hoardix

VOLUME /data
RUN chown hoardix:hoardix /data

USER hoardix
WORKDIR /tmp/

COPY config.example.yaml /etc/hoardix/config.yaml
COPY hoardix /usr/local/bin/hoardix

CMD ["hoardix", "--config-file", "/etc/hoardix/config.yaml"]
