FROM ghcr.io/privacy-scaling-explorations/go-ethereum:latest
COPY docker/geth/init.sh /init.sh
COPY docker/geth/templates /templates
ENTRYPOINT ["/init.sh"]
