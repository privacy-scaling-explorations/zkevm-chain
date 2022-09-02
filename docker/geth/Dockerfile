FROM ghcr.io/privacy-scaling-explorations/go-ethereum:v1.10.23-zkevm
COPY docker/geth/init.sh /init.sh
COPY docker/geth/templates /templates
ENTRYPOINT ["/init.sh"]
