CREATE TABLE IF NOT EXISTS samples_{} (
    ts TIMESTAMP PRIMARY KEY,
    ct BLOB,
    n INT,
);

CREATE TABLE IF NOT EXISTS modules (
    id INT PRIMARY KEY,
    module BLOB,
    debug_id TEXT,
);

CREATE SEQUENCE seq_module_id START 1;