"""
Banksia OS — Test database setup.
Creates a copy of the live schema in a test database for safe testing.
"""
import os, shutil, sqlite3

TEST_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "banksia_os_test.db")
LIVE_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "banksia_os.db")


def create_test_db():
    """Create a test database from the live schema (empty data)."""
    if not os.path.exists(LIVE_DB_PATH):
        raise FileNotFoundError(f"Live database not found at {LIVE_DB_PATH}")

    # Remove old test DB if it exists
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

    # Copy the live DB (includes schema + data)
    shutil.copy2(LIVE_DB_PATH, TEST_DB_PATH)

    # Clear sensitive data from the test copy
    test_conn = sqlite3.connect(TEST_DB_PATH)
    test_conn.row_factory = sqlite3.Row
    cursor = test_conn.cursor()

    # Clear data from all user-facing tables (keep schema)
    tables_to_clear = [
        "tenants", "tenancies", "deposits", "transactions", "rent_charges",
        "applicants", "referencing_forms", "referencing_documents", "guarantors",
        "maintenance_jobs", "maintenance_orders", "maintenance_requests",
        "message_threads", "messages", "comments", "notifications",
        "activity_log", "change_log", "property_images", "entity_documents",
        "contractors", "invoice_items", "company_settings",
    ]

    for table in tables_to_clear:
        try:
            cursor.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            pass  # table might not exist

    # Anonymise properties (keep structure, replace names)
    try:
        properties = cursor.execute("SELECT id, name FROM properties").fetchall()
        for p in properties:
            cursor.execute(
                "UPDATE properties SET name = ?, address_line_1 = ?, address_line_2 = ?, postcode = ? WHERE id = ?",
                [f"Test Property {p['id']}", f"{p['id']} Test Street", "Test Area", "TE1 1ST", p["id"]]
            )
    except sqlite3.OperationalError:
        pass

    # Anonymise units
    try:
        units = cursor.execute("SELECT id, ref FROM units").fetchall()
        for u in units:
            cursor.execute("UPDATE units SET ref = ? WHERE id = ?", [f"TST-{u['id']}", u["id"]])
    except sqlite3.OperationalError:
        pass

    # Anonymise property_owners
    try:
        owners = cursor.execute("SELECT id, name FROM property_owners").fetchall()
        for o in owners:
            cursor.execute("UPDATE property_owners SET name = ?, email = ?, phone = ? WHERE id = ?",
                          [f"Test Owner {o['id']}", f"owner{o['id']}@test.com", "07000000000", o["id"]])
    except sqlite3.OperationalError:
        pass

    # Anonymise company settings
    try:
        cursor.execute("DELETE FROM company_settings")
    except sqlite3.OperationalError:
        pass

    test_conn.commit()
    test_conn.close()

    return TEST_DB_PATH


if __name__ == "__main__":
    path = create_test_db()
    print(f"✅ Test database created at {path}")
    print(f"   Size: {os.path.getsize(path):,} bytes")
