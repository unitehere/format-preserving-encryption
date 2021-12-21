FROM golang:latest

WORKDIR /var/app/current
COPY . .

RUN go install bitbucket.org/liamstask/goose/cmd/goose@latest

EXPOSE 80

CMD ["go", "run", "application.go"]
