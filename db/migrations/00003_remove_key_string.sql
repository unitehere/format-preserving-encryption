-- +goose Up
-- SQL in this section is executed when the migration is applied.
ALTER TABLE arks DROP COLUMN key_string;
-- +goose Down
ALTER TABLE arks ADD COLUMN key_string varchar(32);
-- SQL in this section is executed when the migration is rolled back.
