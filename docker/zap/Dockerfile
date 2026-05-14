FROM ghcr.io/zaproxy/zaproxy:stable

ENV ZAP_PORT=8080 \
    ZAP_JAVA_OPTS="-Xms512m -Xmx1536m"

EXPOSE 8080

CMD ["sh", "-c", "zap.sh -daemon -host 0.0.0.0 -port ${ZAP_PORT} -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"]
