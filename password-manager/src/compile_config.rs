// Path to the SQLite database
pub const DB_PATH: &str = "postgres://defaultuser:changethis@localhost:5432/passworddb"; 

// Enables or disables security features that don't work in the debugger
// Secure password input does not work in the debugger (rpassword)
pub const DEBUG_FLAG: bool = false; 

// Enables or disables single master account mode
// If there is only 1 master, "default" username will be used
pub const SINGLE_MASTER_FLAG: bool = true;