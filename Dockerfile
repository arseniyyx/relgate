FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /relgate ./cmd/relgate

FROM gcr.io/distroless/static-debian12
COPY --from=build /relgate /relgate
COPY relgate.example.yaml /relgate.example.yaml
ENTRYPOINT ["/relgate"]
CMD ["-config", "/relgate.yaml"]
