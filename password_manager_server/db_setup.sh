#!/bin/bash

# Configuration
DB_NAME="passworddb"
DB_USER="defaultuser"
DB_PASSWORD="changethis"
DB_HOST="localhost"
DB_PORT="5432"
DB_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

# Terminate all connections to the existing database
echo "Terminating all connections to the existing database..."
psql -U seanduarte -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${DB_NAME}';"

# Drop the existing database (if it exists)
echo "Dropping existing database if it exists..."
psql -U seanduarte -d postgres -c "DROP DATABASE IF EXISTS ${DB_NAME};"

# Create a new database
echo "Creating new database: ${DB_NAME}..."
psql -U seanduarte -d postgres -c "CREATE DATABASE ${DB_NAME};"

# Grant privileges to the default user (adjust if necessary)
echo "Granting privileges to ${DB_USER} on ${DB_NAME}..."
psql -U seanduarte -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"

# Set the DATABASE_URL environment variable
echo "Setting the DATABASE_URL environment variable..."
export DATABASE_URL="${DB_URL}"
echo "DATABASE_URL set to ${DATABASE_URL}"

# Run migrations (requires sqlx to be installed and migrations folder set up)
echo "Running migrations..."
sqlx migrate run

# Verify the setup by listing tables
echo "Verifying the setup by listing tables..."
psql "${DB_URL}" -c "\d"

echo "Database setup complete!"