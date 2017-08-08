### About

Format preserving encryption implementation of [NIST SP 800-38G](http://dx.doi.org/10.6028/NIST.SP.800-38G).

### Getting Started
1. Get [Govendor](https://github.com/kardianos/govendor)
2. Do `govendor init && govendor add +external`. You now have the required packages in `application.go` in your `/vendor` dir.
3. Set up a MYSQL database. Currently using a database name of `anthem_fpe`.

### Endpoints
All endpoints require a `Authorization` header with a api key.
Note, you need to add a test API key in your `apy_keys` table in `anthem_fpe` database to work. eg `INSERT INTO api_keys SET value="SOMEAPIKEY"`

#### GET/POST encrypt
GET uses the `q` param, eg

`localhost:1234/v1/ark/ff1/encrypt?q=sometext`

POST uses a JSON in the body of your call, eg
`localhost:1234/v1/ark/ff1/encrypt`

```
{
    "values": [
        "sometext"
    ]
}
```

#### GET/POST decrypt
Works the same way as encrypt, with different endpoint name.

### Database Migrations
download cli tool https://github.com/pressly/goose

To migrate
`goose mysql "root@/anthem_fpe?parseTime=true" up`

To see migration history:
`goose mysql "root@/anthem_fpe?parseTime=true" status`
Note the argument `?parseTime=true` 