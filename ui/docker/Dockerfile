FROM node:lts as builder
ADD package.json /build/package.json
WORKDIR /build
RUN yarn install --silent
ADD . /build
RUN ls -al . src/client
RUN ./node_modules/.bin/oats .swagger.yml > /build/src/client/generatedRoutes.ts
RUN yarn build:vendor
ARG INFLUXDB_SHA
RUN NODE_ENV=production ./node_modules/.bin/webpack --config webpack.prod.ts

FROM nginx:stable-alpine
COPY ./docker/nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /build/build /usr/share/nginx/html/
