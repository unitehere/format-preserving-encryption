-- +goose Up
CREATE TABLE api_keys (
  id INT NOT NULL AUTO_INCREMENT,
  value VARCHAR(255) NOT NULL,
  PRIMARY KEY (id)
);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
DROP TABLE IF EXISTS api_keys;