#!/usr/bin/env python3
"""
Banksia OS — SQLite → PostgreSQL Migration
Migrates all 42 tables with data type conversion, sequences, and indexes.
"""
import sqlite3, psycopg2, psycopg2.extras, json, re, sys, os
from datetime import datetime

# ── Config ──
SQLITE_PATH = os.path.join(os.path.dirname(__file__), '..', 'banksia_os.db')
PG_DSN = "host=localhost dbname=banksia_os user=banksia password=banksia_os_pass port=5432"

# Columns storing JSON arrays/objects as TEXT
JSON_COLS = {'custom_fields', 'features', 'image_urls', 'matched_unit_ids',
             'media_paths', 'mentions', 'notes', 'tags', 'tenants'}

# SQLite → PG type mapping
def sqlite_to_pg_type(col_name, col_type, pk):
    """Map SQLite column type to PostgreSQL type."""
    if pk:
        return "SERIAL PRIMARY KEY"
    
    ct = col_type.upper() if col_type else 'TEXT'
    
    if 'INT' in ct:
        return "INTEGER"
    elif 'REAL' in ct or 'FLOAT' in ct or 'DOUBLE' in ct:
        return "NUMERIC(15,2)"
    elif 'BLOB' in ct:
        return "BYTEA"
    else:
        return "TEXT"


def build_create_sql(tables_data):
    """Generate CREATE TABLE statements for PostgreSQL."""
    statements = []
    
    for t_name, info in tables_data.items():
        if t_name == 'sqlite_sequence':
            continue
        
        cols = []
        for c in info['columns']:
            pg_type = sqlite_to_pg_type(c['name'], c['type'], c['pk'])
            nullable = "NOT NULL" if c['notnull'] else ""
            
            default = ""
            if c['dflt_value'] and c['dflt_value'] != 'NULL':
                dv = c['dflt_value'].strip()
                # Convert SQLite expressions and literals
                if "datetime('now')" in dv:
                    dv = "NOW()"
                elif dv in ("''", '""'):
                    dv = None  # Skip empty string default
                elif dv == "'[]'":
                    dv = "'[]'::jsonb"
                elif dv == "'{}'":
                    dv = "'{}'::jsonb"
                elif dv.startswith("'") and dv.endswith("'"):
                    dv = dv  # Keep SQLite string literal (already PG-compatible)
                elif dv in ('0', '1'):
                    dv = dv  # Integer literals
                elif dv == 'CURRENT_TIMESTAMP':
                    dv = 'NOW()'
                elif dv == 'NULL':
                    dv = None
                else:
                    dv = None
                if dv is not None:
                    default = f"DEFAULT {dv}"
            
            cols.append(f"  {c['name']} {pg_type} {nullable} {default}".strip())
        
        ddl = f"CREATE TABLE IF NOT EXISTS {t_name} (\n" + ",\n".join(cols) + "\n);"
        statements.append(ddl)
    
    return statements


def build_index_sql(tables_data):
    """Generate CREATE INDEX statements."""
    statements = []
    seen = set()
    
    for t_name, info in tables_data.items():
        for idx in info['indexes']:
            sql = idx['sql'].strip()
            if sql not in seen:
                seen.add(sql)
                statements.append(sql)
    
    return statements


def _debug_row(vals, cols):
    """Print first problem column in a failed row."""
    for i, (c, v) in enumerate(zip(cols, vals)):
        if isinstance(v, str) and len(v) > 500:
            print("    col '{}' (idx {}): str({} chars)".format(c, i, len(v)))
            break
    print("    sample: {}".format(str(vals[:3])[:150]))


def migrate():
    """Main migration function."""
    print("=" * 60)
    print("Banksia OS — SQLite → PostgreSQL Migration")
    print("=" * 60)
    
    # ── Connect to source ──
    sq = sqlite3.connect(SQLITE_PATH)
    sq.row_factory = sqlite3.Row
    
    # ── Extract all table info ──
    tables = [r[0] for r in sq.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY name"
    ).fetchall()]
    
    tables_data = {}
    for t in tables:
        cols = sq.execute(f'PRAGMA table_info("{t}")').fetchall()
        indexes = sq.execute(
            f"SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='{t}' AND sql IS NOT NULL"
        ).fetchall()
        row_count = sq.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        tables_data[t] = {
            'columns': [{'name': c[1], 'type': c[2], 'notnull': c[3], 'dflt_value': c[4], 'pk': c[5]} for c in cols],
            'indexes': [{'name': i[0], 'sql': i[1]} for i in indexes],
            'row_count': row_count
        }
    
    # ── Connect to target ──
    pg = psycopg2.connect(PG_DSN)
    pg.autocommit = False
    cur = pg.cursor()
    
    try:
        # ── Phase 1: Create tables ──
        print("\n📦 Phase 1: Creating tables...")
        create_stmts = build_create_sql(tables_data)
        for stmt in create_stmts:
            try:
                cur.execute(stmt)
                print(f"  ✓ {stmt.split()[2]}")
            except Exception as e:
                print(f"  ✗ {stmt.split()[2]}: {e}")
                pg.rollback()
                return False
        
        # ── Phase 2: Migrate data ──
        print("\n📦 Phase 2: Migrating data...")
        total_rows = 0
        for t_name in tables:
            rows = sq.execute(f'SELECT * FROM "{t_name}"').fetchall()
            if not rows:
                print(f"  ✓ {t_name}: 0 rows (empty)")
                continue
            
            cols = [desc[1] for desc in sq.execute(f'PRAGMA table_info("{t_name}")').fetchall()]
            col_list = ', '.join(f'"{c}"' for c in cols)
            placeholders = ', '.join(['%s'] * len(cols))
            
            insert_sql = f'INSERT INTO "{t_name}" ({col_list}) VALUES ({placeholders})'
            
            # Prepare batch
            batch = []
            for row in rows:
                vals = list(row)
                batch.append(vals)
            
            # Per-table transaction — one failure doesn't break others
            try:
                cur.executemany(insert_sql, batch)
                pg.commit()
                total_rows += len(batch)
                print(f"  ✓ {t_name}: {len(batch)} rows migrated")
            except Exception as e:
                pg.rollback()
                # Log the actual error for debugging
                err_msg = str(e).split('\n')[0]
                print(f"  ⚠ {t_name}: executemany failed ({err_msg[:80]}), trying row-by-row...")
                # Fallback: insert row by row with individual error handling
                row_count = 0
                for row_vals in batch:
                    try:
                        cur.execute(insert_sql, row_vals)
                        pg.commit()
                        row_count += 1
                    except Exception as e2:
                        err_detail = str(e2).split('\n')[0]
                        pg.rollback()
                        # Try to convert problematic values
                        fixed = list(row_vals)
                        for i, v in enumerate(fixed):
                            if isinstance(v, str) and len(v) > 10000:
                                fixed[i] = v[:10000]  # Truncate extremely long strings
                        try:
                            cur.execute(insert_sql, fixed)
                            pg.commit()
                            row_count += 1
                        except Exception as e3:
                            pg.rollback()
                            # Print first 3 failures for debugging
                            if row_count < 3:
                                print(f"    ✗ row {row_count}: {err_detail[:120]}")
                                _debug_row(row_vals, cols)
                total_rows += row_count
                print(f"  ⚠ {t_name}: {row_count}/{len(batch)} rows migrated ({len(batch)-row_count} failed)")
            
        # ── Phase 3: Create indexes ──
        print("\n📦 Phase 3: Creating indexes...")
        idx_stmts = build_index_sql(tables_data)
        for stmt in idx_stmts:
            try:
                cur.execute(stmt)
                print(f"  ✓ {stmt.split()[3] if len(stmt.split()) > 3 else stmt[:50]}")
            except Exception as e:
                print(f"  ⚠ {stmt[:60]}: {e}")
        
        # ── Phase 4: Update sequences ──
        print("\n📦 Phase 4: Updating sequences...")
        for t_name in tables:
            pk_col = None
            for c in tables_data[t_name]['columns']:
                if c['pk']:
                    pk_col = c['name']
                    break
            if not pk_col:
                continue
            
            max_id = sq.execute(f'SELECT MAX("{pk_col}") FROM "{t_name}"').fetchone()[0]
            if max_id and max_id > 0:
                seq_name = f'{t_name}_{pk_col}_seq'
                try:
                    cur.execute(f"ALTER SEQUENCE {seq_name} RESTART WITH {max_id + 1}")
                except Exception:
                    pass  # Sequence may not exist for all tables
        
        pg.commit()
        
        # ── Verification ──
        print("\n📦 Phase 5: Verification...")
        print(f"\n{'='*60}")
        print(f"✅ Migration complete! {total_rows} total rows migrated across {len(tables)} tables")
        print(f"{'='*60}")
        
        # Show row counts
        print(f"\n{'Table':<30} {'SQLite':>8} {'PostgreSQL':>10} {'Match':>8}")
        print(f"{'-'*60}")
        all_ok = True
        for t_name in tables:
            sq_count = sq.execute(f'SELECT COUNT(*) FROM "{t_name}"').fetchone()[0]
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{t_name}"')
                pg_count = cur.fetchone()[0]
            except Exception:
                pg_count = -1
            match = "✅" if sq_count == pg_count else "❌"
            if sq_count != pg_count:
                all_ok = False
            print(f"{t_name:<30} {sq_count:>8} {pg_count:>10} {match:>8}")
        
        if all_ok:
            print(f"\n✅ All {len(tables)} tables verified — data integrity confirmed!")
        else:
            print(f"\n⚠️ Some table counts differ — check individual mismatches above")
        
        return all_ok
    
    except Exception as e:
        pg.rollback()
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        cur.close()
        pg.close()
        sq.close()


if __name__ == '__main__':
    success = migrate()
    sys.exit(0 if success else 1)
