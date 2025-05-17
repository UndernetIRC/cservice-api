FROM alpine
RUN apk add --update --no-cache ca-certificates

FROM scratch
COPY cservice-api /cservice-api
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8080/tcp
ENTRYPOINT ["/cservice-api"]
