FROM alpine
LABEL maintainer "Thomas Kastner <tom@sprungknoedl.at>"

RUN apk add --no-cache ca-certificates

COPY rps-export /app/rps-export
COPY templates /app/templates
COPY assets /app/assets

ENV PORT=8080
EXPOSE 8080

WORKDIR /app
CMD ["/app/rps-export"]
