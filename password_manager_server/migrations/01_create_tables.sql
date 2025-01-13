CREATE TABLE IF NOT EXISTS masters (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL CHECK (length(username) > 0),
    password TEXT NOT NULL CHECK (length(password) > 0)
);

CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(name) > 0),
    url TEXT,
    username TEXT NOT NULL CHECK (length(username) > 0),
    password TEXT NOT NULL CHECK (length(password) > 0),
    description TEXT,
    master_id INTEGER NOT NULL REFERENCES masters(id) ON DELETE CASCADE
);