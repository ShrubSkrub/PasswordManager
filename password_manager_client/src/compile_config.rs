// Enables or disables security features that don't work in the debugger
// Secure password input does not work in the debugger (rpassword)
pub const DEBUG_FLAG: bool = false;

// Path to the SQLite database
pub const DB_PATH: &str = "postgres://defaultuser:changethis@localhost:5432/passworddb"; 