FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mossward ./cmd/mossward

FROM alpine:3.22

RUN addgroup -S mossward && adduser -S -G mossward mossward
WORKDIR /app
COPY --from=build /out/mossward /usr/local/bin/mossward
RUN mkdir /app/data && chown mossward:mossward /app/data
USER mossward

ENV MOSSWARD_DATABASE_FILE=/app/data/mossward.db
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/mossward"]
