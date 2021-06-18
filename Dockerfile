FROM golang:1.16.5

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY main.go ./
COPY ./pkg ./pkg

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hoardix .


FROM alpine:3.13

RUN apk --no-cache add ca-certificates

USER nobody
WORKDIR /tmp/

COPY --from=0 /app/hoardix /usr/local/bin/hoardix

CMD ["hoardix"]
