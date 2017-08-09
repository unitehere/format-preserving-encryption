-- +goose Up
-- SQL in this section is executed when the migration is applied.
CREATE TABLE arks (
  ark_name varchar(255) NOT NULL,
  algorithm_type varchar(5) NOT NULL,
  key_string varchar(32) NOT NULL,
  radix SMALLINT UNSIGNED NOT NULL,
  min_message_length INT UNSIGNED NOT NULL,
  max_message_length INT UNSIGNED NOT NULL,
  max_tweak_length INT UNSIGNED,
  PRIMARY KEY (ark_name)
);
-- +goose Down
DROP TABLE IF EXISTS arks;
-- SQL in this section is executed when the migration is rolled back.
