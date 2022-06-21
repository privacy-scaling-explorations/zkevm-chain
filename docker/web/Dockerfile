# https://github.com/privacy-scaling-explorations/hop/commit/e09a43ca270d4d0c7be63751c95ad037f1f68723
FROM ghcr.io/privacy-scaling-explorations/hop/hop-frontend@sha256:cf8ef7061033fb2d8f349523baaee4b62859799e7e00d5be103023b0107b2b58 AS hop
# nginx 1.21.6
FROM nginx@sha256:2bcabc23b45489fb0885d69a06ba1d648aeda973fae7bb981bafbb884165e514
COPY --from=hop /www /www
COPY docker/web/nginx.conf /etc/nginx/nginx.conf
