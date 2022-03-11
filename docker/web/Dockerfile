FROM node:14-alpine as builder
WORKDIR /
RUN apk add git alpine-sdk python3
RUN git clone --depth=1 https://github.com/appliedzkp/hop.git
WORKDIR /hop
RUN yarn install && yarn lerna bootstrap

WORKDIR hop/packages/frontend
RUN REACT_APP_NETWORK=devnet yarn build

FROM nginx
COPY --from=builder /hop/packages/frontend/build /www
COPY docker/web/nginx.conf /etc/nginx/nginx.conf
