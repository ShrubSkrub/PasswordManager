CREATE TABLE IF NOT EXISTS masters (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    description TEXT,
    master_id INTEGER NOT NULL REFERENCES masters(id) ON DELETE CASCADE
);