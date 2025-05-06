/**
 * Secure Access System - C Implementation with SQLite
 * 
 * This program implements a password-based security system with:
 * - User registration and authentication
 * - SQLite database storage
 * - Password hashing
 * - Login attempt tracking
 * - Access logging
 * - Random secure data generation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <openssl/sha.h>

// Constants
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_BUFFER_LENGTH 256
#define MAX_ATTEMPTS 3
#define DB_FILE "secure_access.db"
#define SECURE_DATA_LENGTH 16

// Function prototypes
bool initialize_database();
char* hash_password(const char* password);
bool register_user(const char* username, const char* password);
bool verify_user(const char* username, const char* password);
bool username_exists(const char* username);
void log_access(const char* username, const char* action, const char* status);
void generate_secure_data(char* output, size_t length);
void display_menu();
void process_login();
void process_registration();
void display_secure_content(const char* username);
void display_account_info(const char* username);
void display_access_logs(const char* username);
void clear_screen();
void pause_screen();

// Global variables
sqlite3* db = NULL;
int login_attempts = 0;

/**
 * Main function
 */
int main() {
    // Seed random number generator
    srand(time(NULL));
    
    // Initialize the database
    if (!initialize_database()) {
        fprintf(stderr, "Failed to initialize database. Exiting...\n");
        return 1;
    }
    
    int choice = 0;
    bool running = true;
    
    // Main program loop
    while (running) {
        clear_screen();
        printf("\n\n");
        printf("╔══════════════════════════════════════════╗\n");
        printf("║      SECURE ACCESS SYSTEM v1.0           ║\n");
        printf("╚══════════════════════════════════════════╝\n\n");
        
        display_menu();
        printf("\nSelect an option: ");
        scanf("%d", &choice);
        getchar(); // Clear input buffer
        
        switch (choice) {
            case 1:
                process_login();
                break;
            case 2:
                process_registration();
                break;
            case 3:
                printf("\nExiting the system...\n");
                running = false;
                break;
            default:
                printf("\nInvalid option. Please try again.\n");
                pause_screen();
                break;
        }
    }
    
    // Close database connection
    if (db) {
        sqlite3_close(db);
    }
    
    return 0;
}

/**
 * Initialize SQLite database and create tables if they don't exist
 */
bool initialize_database() {
    int rc = sqlite3_open(DB_FILE, &db);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return false;
    }
    
    // Create users table
    char* sql = "CREATE TABLE IF NOT EXISTS users ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "username TEXT UNIQUE NOT NULL,"
                "password_hash TEXT NOT NULL,"
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "last_login TIMESTAMP"
                ");";
    
    rc = sqlite3_exec(db, sql, NULL, 0, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return false;
    }
    
    // Create access logs table
    sql = "CREATE TABLE IF NOT EXISTS access_logs ("
          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
          "username TEXT NOT NULL,"
          "action TEXT NOT NULL,"
          "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
          "status TEXT NOT NULL"
          ");";
    
    rc = sqlite3_exec(db, sql, NULL, 0, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return false;
    }
    
    return true;
}

/**
 * Hash password using SHA-256
 */
char* hash_password(const char* password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);
    
    char* output = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (output == NULL) {
        return NULL;
    }
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    
    return output;
}

/**
 * Register a new user in the database
 */
bool register_user(const char* username, const char* password) {
    if (username_exists(username)) {
        return false;
    }
    
    char* password_hash = hash_password(password);
    if (password_hash == NULL) {
        return false;
    }
    
    char sql[MAX_BUFFER_LENGTH];
    snprintf(sql, MAX_BUFFER_LENGTH, "INSERT INTO users (username, password_hash) VALUES ('%s', '%s');", 
             username, password_hash);
    
    int rc = sqlite3_exec(db, sql, NULL, 0, NULL);
    free(password_hash);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        log_access(username, "registration", "failed");
        return false;
    }
    
    log_access(username, "registration", "success");
    return true;
}

/**
 * Verify user credentials
 */
bool verify_user(const char* username, const char* password) {
    char* password_hash = hash_password(password);
    if (password_hash == NULL) {
        return false;
    }
    
    char sql[MAX_BUFFER_LENGTH];
    snprintf(sql, MAX_BUFFER_LENGTH, "SELECT id FROM users WHERE username = '%s' AND password_hash = '%s';", 
             username, password_hash);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    free(password_hash);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return false;
    }
    
    rc = sqlite3_step(stmt);
    bool result = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);
    
    if (result) {
        // Update last login time
        snprintf(sql, MAX_BUFFER_LENGTH, "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = '%s';", 
                 username);
        sqlite3_exec(db, sql, NULL, 0, NULL);
        log_access(username, "login", "success");
    } else {
        log_access(username, "login", "failed");
    }
    
    return result;
}

/**
 * Check if a username already exists
 */
bool username_exists(const char* username) {
    char sql[MAX_BUFFER_LENGTH];
    snprintf(sql, MAX_BUFFER_LENGTH, "SELECT id FROM users WHERE username = '%s';", username);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return false;
    }
    
    rc = sqlite3_step(stmt);
    bool result = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);
    
    return result;
}

/**
 * Log user actions in the database
 */
void log_access(const char* username, const char* action, const char* status) {
    char sql[MAX_BUFFER_LENGTH];
    snprintf(sql, MAX_BUFFER_LENGTH, 
             "INSERT INTO access_logs (username, action, status) VALUES ('%s', '%s', '%s');",
             username, action, status);
    
    int rc = sqlite3_exec(db, sql, NULL, 0, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error in logging: %s\n", sqlite3_errmsg(db));
    }
}

/**
 * Generate random secure data
 */
void generate_secure_data(char* output, size_t length) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    // Pattern selection (1-3)
    int pattern = rand() % 3 + 1;
    
    if (pattern == 1) {
        // Format: ABC-1234-DEF-5678
        char segment1[4], segment2[5], segment3[4], segment4[5];
        
        for (int i = 0; i < 3; i++) {
            segment1[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        segment1[3] = '\0';
        
        for (int i = 0; i < 4; i++) {
            segment2[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        segment2[4] = '\0';
        
        for (int i = 0; i < 3; i++) {
            segment3[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        segment3[3] = '\0';
        
        for (int i = 0; i < 4; i++) {
            segment4[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        segment4[4] = '\0';
        
        snprintf(output, length, "%s-%s-%s-%s", segment1, segment2, segment3, segment4);
    } else if (pattern == 2) {
        // Format: SEC-ABCDEF-1234
        char segment1[7], segment2[5];
        
        for (int i = 0; i < 6; i++) {
            segment1[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        segment1[6] = '\0';
        
        for (int i = 0; i < 4; i++) {
            segment2[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        segment2[4] = '\0';
        
        snprintf(output, length, "SEC-%s-%s", segment1, segment2);
    } else {
        // Format: AB1234-CDEF5678
        char segment1[7], segment2[9];
        
        segment1[0] = charset[rand() % 26]; // First two chars are letters
        segment1[1] = charset[rand() % 26];
        
        for (int i = 2; i < 6; i++) {
            segment1[i] = charset[26 + rand() % 10]; // Next four chars are digits
        }
        segment1[6] = '\0';
        
        for (int i = 0; i < 8; i++) {
            segment2[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        segment2[8] = '\0';
        
        snprintf(output, length, "%s-%s", segment1, segment2);
    }
}

/**
 * Display the main menu
 */
void display_menu() {
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  1. Login to System                      ║\n");
    printf("║  2. Register New Account                 ║\n");
    printf("║  3. Exit                                 ║\n");
    printf("╚══════════════════════════════════════════╝\n");
}

/**
 * Process user login
 */
void process_login() {
    clear_screen();
    printf("\n\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║              SYSTEM LOGIN                ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    
    if (login_attempts >= MAX_ATTEMPTS) {
        printf("⚠️  Too many failed login attempts! System locked.\n");
        printf("\nPress Enter to continue...");
        getchar();
        login_attempts = 0; // Reset for simplicity in this example
        return;
    }
    
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    
    printf("Username: ");
    fgets(username, MAX_USERNAME_LENGTH, stdin);
    username[strcspn(username, "\n")] = 0; // Remove newline
    
    printf("Password: ");
    fgets(password, MAX_PASSWORD_LENGTH, stdin);
    password[strcspn(password, "\n")] = 0; // Remove newline
    
    if (verify_user(username, password)) {
        login_attempts = 0; // Reset attempts on successful login
        display_secure_content(username);
    } else {
        login_attempts++;
        printf("\n❌ Login failed! Invalid username or password.\n");
        printf("Attempts remaining: %d\n", MAX_ATTEMPTS - login_attempts);
        pause_screen();
    }
}

/**
 * Process user registration
 */
void process_registration() {
    clear_screen();
    printf("\n\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║           ACCOUNT REGISTRATION           ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char confirm_password[MAX_PASSWORD_LENGTH];
    
    printf("Choose Username: ");
    fgets(username, MAX_USERNAME_LENGTH, stdin);
    username[strcspn(username, "\n")] = 0; // Remove newline
    
    printf("Choose Password: ");
    fgets(password, MAX_PASSWORD_LENGTH, stdin);
    password[strcspn(password, "\n")] = 0; // Remove newline
    
    printf("Confirm Password: ");
    fgets(confirm_password, MAX_PASSWORD_LENGTH, stdin);
    confirm_password[strcspn(confirm_password, "\n")] = 0; // Remove newline
    
    if (strlen(username) < 3) {
        printf("\n❌ Username must be at least 3 characters long.\n");
    } else if (strlen(password) < 4) {
        printf("\n❌ Password must be at least 4 characters long.\n");
    } else if (strcmp(password, confirm_password) != 0) {
        printf("\n❌ Passwords do not match.\n");
    } else if (username_exists(username)) {
        printf("\n❌ Username already exists. Please choose another.\n");
    } else {
        if (register_user(username, password)) {
            printf("\n✅ Registration successful! You can now login.\n");
        } else {
            printf("\n❌ Registration failed. Please try again.\n");
        }
    }
    
    pause_screen();
}

/**
 * Display secure content after successful login
 */
void display_secure_content(const char* username) {
    bool logged_in = true;
    
    while (logged_in) {
        clear_screen();
        printf("\n\n");
        printf("╔══════════════════════════════════════════╗\n");
        printf("║            SECURE ACCESS AREA            ║\n");
        printf("╚══════════════════════════════════════════╝\n\n");
        
        printf("Welcome, %s!\n\n", username);
        
        printf("╔══════════════════════════════════════════╗\n");
        printf("║  1. View Secure Data                     ║\n");
        printf("║  2. Account Information                  ║\n");
        printf("║  3. Access Logs                          ║\n");
        printf("║  4. Logout                               ║\n");
        printf("╚══════════════════════════════════════════╝\n");
        
        int choice;
        printf("\nSelect an option: ");
        scanf("%d", &choice);
        getchar(); // Clear input buffer
        
        switch (choice) {
            case 1: {
                clear_screen();
                printf("\n\n");
                printf("╔══════════════════════════════════════════╗\n");
                printf("║             SECURE DATA                  ║\n");
                printf("╚══════════════════════════════════════════╝\n\n");
                
                char secure_data[MAX_BUFFER_LENGTH];
                generate_secure_data(secure_data, MAX_BUFFER_LENGTH);
                
                printf("Your secure access code is:\n\n");
                printf("    \033[1;33m%s\033[0m\n\n", secure_data);
                printf("This is your unique secure key. Do not share it with anyone.\n");
                
                pause_screen();
                break;
            }
            case 2:
                display_account_info(username);
                break;
            case 3:
                display_access_logs(username);
                break;
            case 4:
                log_access(username, "logout", "success");
                logged_in = false;
                printf("\nLogged out successfully.\n");
                pause_screen();
                break;
            default:
                printf("\nInvalid option. Please try again.\n");
                pause_screen();
                break;
        }
    }
}

/**
 * Display account information
 */
void display_account_info(const char* username) {
    clear_screen();
    printf("\n\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║          ACCOUNT INFORMATION             ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    
    char sql[MAX_BUFFER_LENGTH];
    snprintf(sql, MAX_BUFFER_LENGTH, 
             "SELECT created_at, last_login FROM users WHERE username = '%s';", 
             username);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        pause_screen();
        return;
    }
    
    rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_ROW) {
        const char* created_at = (const char*)sqlite3_column_text(stmt, 0);
        const char* last_login = (const char*)sqlite3_column_text(stmt, 1);
        
        printf("Username:       %s\n", username);
        printf("Created:        %s\n", created_at ? created_at : "N/A");
        printf("Last Login:     %s\n", last_login ? last_login : "N/A");
    } else {
        printf("Error: Could not retrieve account information.\n");
    }
    
    sqlite3_finalize(stmt);
    pause_screen();
}

/**
 * Display access logs
 */
void display_access_logs(const char* username) {
    clear_screen();
    printf("\n\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║              ACCESS LOGS                 ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    
    char sql[MAX_BUFFER_LENGTH];
    snprintf(sql, MAX_BUFFER_LENGTH, 
             "SELECT action, timestamp, status FROM access_logs "
             "WHERE username = '%s' ORDER BY timestamp DESC LIMIT 10;", 
             username);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        pause_screen();
        return;
    }
    
    printf("Recent access logs:\n\n");
    
    bool has_logs = false;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        has_logs = true;
        const char* action = (const char*)sqlite3_column_text(stmt, 0);
        const char* timestamp = (const char*)sqlite3_column_text(stmt, 1);
        const char* status = (const char*)sqlite3_column_text(stmt, 2);
        
        const char* status_symbol = strcmp(status, "success") == 0 ? "✅" : "❌";
        
        printf("%s %s - %s at %s\n", 
               status_symbol, 
               action ? action : "unknown", 
               status ? status : "unknown", 
               timestamp ? timestamp : "unknown time");
    }
    
    if (!has_logs) {
        printf("No access logs found.\n");
    }
    
    sqlite3_finalize(stmt);
    pause_screen();
}

/**
 * Clear the console screen
 */
void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

/**
 * Pause the screen and wait for user input
 */
void pause_screen() {
    printf("\nPress Enter to continue...");
    getchar();
}
