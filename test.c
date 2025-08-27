/*
  WARNING: This program is intentionally insecure and incorrect.
  It demonstrates MANY violations of common CERT C rules.
  Do NOT copy patterns from here into real code.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>

char *return_stack_pointer(void) {
    char local[8] = "oops";
    return local;
}


void use_after_free(void) {
    char *p = (char*)malloc(4);               
    strcpy(p, "xxx");                         
    free(p);
    p[0] = 'y';                            
    free(p);                                 
}

/* Modifying a string literal */
// Violation: STR30-C
void modify_string_literal(void) {
    char *s = "hello";
    s[0] = 'H'; // undefined behavior
}

/* Unchecked/unsafe input causing buffer overflow */
// Violations: FIO30-C / STR31-C
void overflow_input(void) {
    char buf[8];
    // No bounds specified — classic overflow risk
    scanf("%s", buf); // ignoring return value too (ERR33-C)
    printf("You typed: %s\n", buf);
}

/* Format string vulnerability */
// Violation: FIO30-C (uncontrolled format string)
void format_string_vuln(const char *user) {
    // If 'user' contains %n etc., it's game over
    printf(user); // DO NOT DO THIS
    printf("\n");
}

/* Integer overflow and shifting negatives / overshifting */
// Violations: INT30-C, INT34-C
void integer_ub(void) {
    int x = INT_MAX;
    x += 1; // signed overflow UB
    int y = -1;
    int z = y << 2; // shift of negative
    int w = 1 << 31; // overshift in 32-bit int
    (void)x; (void)z; (void)w;
}

/* Signed/unsigned mix-ups */
// Violation: INT31-C
void signed_unsigned_mix(void) {
    int neg = -5;
    size_t sz = neg;        // Converts to huge size_t
    if (sz > 10) {
        puts("Unexpected path due to sign conversion.");
    }
}

/* Uninitialized read */
// Violation: EXP33-C
void uninitialized_read(void) {
    int u;
    if (u) { // reading indeterminate value
        puts("Uninitialized branch taken.");
    }
}

/* Out-of-bounds access */
// Violation: ARR30-C
void out_of_bounds(void) {
    int a[5] = {0};
    a[5] = 42; // write past the end
}

/* Null pointer dereference */
// Violation: EXP34-C
void null_deref(void) {
    char *p = NULL;
    puts(p); // dereference/usage of NULL
}

/* Ignored return values & lack of error handling */
// Violations: ERR33-C, FIO34-C
void ignore_returns(void) {
    FILE *f = fopen("maybe.txt", "w"); // ignoring NULL check
    fputs("data", f);                  // ignoring return value
    fclose(f);                         // ignoring return value
    remove("not_there.txt");           // ignoring failure
}

/* Insecure temporary file creation (race) */
// Violation: FIO21-C / POSIX temp-file race
void temp_file_race(void) {
    char name[L_tmpnam];
    tmpnam(name); // insecure
    FILE *f = fopen(name, "w"); // race window; not O_EXCL
    if (f) {
        fputs("temp", f);
        fclose(f);
    }
}

/* TOCTOU (time-of-check, time-of-use) pattern */
// Violation: FIO45-C style (avoid TOCTOU)
void toctou_demo(void) {
    struct stat st;
    if (stat("guarded.txt", &st) == 0) {
        // File properties could change here
        FILE *f = fopen("guarded.txt", "w"); // Assumes earlier check still valid
        if (f) {
            fputs("overwrite", f);
            fclose(f);
        }
    }
}

/* Command injection: passing environment/user-controlled data to system() */
// Violation: ENV00-C / MSC24-C
void command_injection(void) {
    const char *cmd = getenv("UNSAFE_CMD"); // attacker-controlled
    if (cmd) {
        system(cmd); // executing untrusted command
    }
}

/* Insecure randomness for security use */
// Violation: MSC30-C
void insecure_random(void) {
    // Using rand() for anything security-related is a no-no
    int token = rand(); // no seeding, not cryptographically secure
    printf("Fake token: %d\n", token);
}

/* Reading past string bounds by incorrect length assumptions */
// Violation: STR31-C
void bad_strncpy(void) {
    char dst[4];
    // Misused strncpy: may not null-terminate; also source bigger than dest
    strncpy(dst, "toolong", sizeof(dst));
    printf("dst maybe not terminated: %s\n", dst); // potential overread
}

/* Leaking sensitive info via stdout (no redaction) */
// Violation: MSC37-C (do not leak sensitive info)
void leak_info(void) {
    char password_in_memory[] = "p@ssw0rd";
    printf("Debug: password=%s\n", password_in_memory); // leaks secrets
}

int main(int argc, char **argv) {
    puts("Starting intentionally-bad demo…");

    // Many independent calls to show separate violations.
    use_after_free();
    modify_string_literal();
    overflow_input();
    format_string_vuln(argc > 1 ? argv[1] : "user%p%p%n");
    integer_ub();
    signed_unsigned_mix();
    uninitialized_read();
    out_of_bounds();
    null_deref();
    ignore_returns();
    temp_file_race();
    toctou_demo();
    command_injection();
    insecure_random();
    bad_strncpy();
    leak_info();

    // Returning pointer to stack memory, then using it
    char *dangling = return_stack_pointer();
    printf("Dangling says: %s\n", dangling); // UB

    puts("Done (if we even got here).");
    return 0;
}
