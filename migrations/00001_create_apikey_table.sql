-- +goose Up
CREATE TABLE api_keys (
  id int NOT NULL AUTO_INCREMENT,
  value varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
DROP TABLE IF EXISTS api_keys;