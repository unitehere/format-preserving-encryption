### About

Format preserving encryption implementation of [NIST SP 800-38G](http://dx.doi.org/10.6028/NIST.SP.800-38G).

### AWS Credentials Setup
For local development:
1. Open a terminal window and run the AWS CLI setup. Use your personal Access ID
   and personal Access Secret when prompted
2. Navigate to the `.aws` folder within the home directory and open `credentials`
3. Make sure you have the `format-preserving-encryption` profile credentials configured:

```
[format-preserving-encryption]
aws_access_key_id = XXXXXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

4. Save and close the file.
5. Open the `config` file in the same `.aws` directory.
6. Make sure you have the `format-preserving-encryption` profile configured:

```
[profile format-preserving-encryption]
output = json
region = us-west-2
```

### Getting Started
1. Get [Govendor](https://github.com/kardianos/govendor)
2. Do `govendor init && govendor add +external`. You now have the required packages in `application.go` in your `/vendor` dir.
3. Set up a MYSQL database. Currently using a database name of `anthem_fpe`.
4. Run the instructions under Database Migrations and migrate your db
5. Queries you should probably run to seed your development db:
    - add the ark bestArk to your table

    `insert into arks values ("bestArk", "ff1", "2B7E151628AED2A6ABF7158809CF4F3C", 36, 2, 20 ,16)`
    - add an api key of your choosing, using 12345 as an example

    `INSERT INTO api_keys SET value="12345"`

### Endpoints
All endpoints require a `Authorization` header with a api key.

#### GET/POST encrypt
GET uses the `q` param, eg

`localhost:1234/v1/ark/bestArk/encrypt?q=sometext`

POST uses a JSON in the body of your call, eg
`localhost:1234/v1/ark/bestArk/encrypt`

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
Get the correct goose:
`go get bitbucket.org/liamstask/goose/cmd/goose`

To configure, edit `db/dbconf.yml`. If you don't yet have a `dbconf.yml`, copy `dbconf.yml.example` to `dbconf.yml` and make the necessary edits.

To migrate use `goose up`

### Service Deployment
To deploy the application using Elastic Beanstalk for the first time, you will need to run:
`eb init`

The region you want to deploy to is us-west-2, and the application you want to deploy to is `uh-fpe`.

In order to deploy, make sure you have `db/dbconf.yml` correctly configured and have a `production` environment set up.

Before deploying, run `goose -env production up`.

To deploy, run `eb deploy`.
