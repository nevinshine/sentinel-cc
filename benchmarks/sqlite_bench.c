/* sqlite_bench.c — Sentinel-CC SQLite throughput benchmark
 * Inserts N rows + reads them back, prints ops/sec.
 * Build: cc -O2 benchmarks/sqlite_bench.c -lsqlite3 -o benchmarks/sqlite_bench
 */
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NUM_OPS 10000

int main(int argc, char **argv) {
  const char *db_path = (argc > 1) ? argv[1] : "/tmp/sentinel_bench.db";
  sqlite3 *db;
  if (sqlite3_open(db_path, &db) != SQLITE_OK) {
    fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
    return 1;
  }

  sqlite3_exec(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;", 0, 0, 0);
  sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS bench(id INTEGER PRIMARY KEY, val TEXT);", 0, 0, 0);

  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);

  sqlite3_exec(db, "BEGIN;", 0, 0, 0);
  sqlite3_stmt *ins;
  sqlite3_prepare_v2(db, "INSERT INTO bench(val) VALUES(?1);", -1, &ins, 0);
  for (int i = 0; i < NUM_OPS; i++) {
    char buf[32];
    snprintf(buf, sizeof(buf), "row_%d", i);
    sqlite3_bind_text(ins, 1, buf, -1, SQLITE_TRANSIENT);
    sqlite3_step(ins);
    sqlite3_reset(ins);
  }
  sqlite3_finalize(ins);
  sqlite3_exec(db, "COMMIT;", 0, 0, 0);

  // Read back
  sqlite3_stmt *sel;
  sqlite3_prepare_v2(db, "SELECT val FROM bench;", -1, &sel, 0);
  int count = 0;
  while (sqlite3_step(sel) == SQLITE_ROW)
    count++;
  sqlite3_finalize(sel);

  clock_gettime(CLOCK_MONOTONIC, &t1);
  double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
  long ops_per_sec = (long)((NUM_OPS + count) / elapsed);

  printf("SQLITE_OPS_PER_SEC=%ld\n", ops_per_sec);
  sqlite3_close(db);
  return 0;
}
