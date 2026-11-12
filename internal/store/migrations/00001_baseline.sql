-- Baseline: no schema yet. The first tables come with #2's data model.
-- goose records this version in goose_db_version, so the first real
-- migration is 00002.

-- +goose Up
SELECT 1;

-- +goose Down
SELECT 1;
