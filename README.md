### About

Format preserving encryption implementation of [NIST SP 800-38G](http://dx.doi.org/10.6028/NIST.SP.800-38G).

### AWS Credentials Setup
For local development:
1. Open a terminal window and run the AWS CLI setup. Use your personal Access ID
   and personal Access Secret when prompted
2. Navigate to the `.aws` folder within the home directory and open `credentials`
3. The first 3 lines should remain as the same, and the rest of the file should look as follows:
[default]
aws_access_key_id = YYYYYYYYYYYYYYYYYYYY
aws_secret_access_key = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY

[format-preserving-encryption]
aws_access_key_id = XXXXXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

4. Save and close the file.

For production environment:
1. Open the `credentials.example` file and enter the production access keys id and secret access key into both profiles.
2. Open terminal window and create folder `.aws` at home directory (if the folder does not already exist)
3. Copy the modified `credentials.example` file into the `.aws` folder, and rename the file `credentials`.

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
