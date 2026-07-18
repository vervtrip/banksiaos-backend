"""
Banksia OS — Finance service layer.
Invoices, deposits, transactions, rent schedules, financial reporting.
"""
from datetime import datetime, timedelta
from banksia_os_db import get_dict_db
from services.db_service import json_success, json_error, paginate, int_param, float_param, record_change
from services.activity_service import log_activity


def calculate_arrears(db=None):
    """Calculate total arrears across all active tenancies."""
    close_db = db is None
    if close_db:
        db = get_dict_db()
    try:
        rows = db.execute("""
            SELECT t.id, t.unit_id, t.rent_amount, t.rent_frequency,
                   COALESCE(SUM(CASE WHEN rc.paid = 0 THEN rc.amount ELSE 0 END), 0) AS unpaid
            FROM tenancies t
            LEFT JOIN rent_charges rc ON rc.tenancy_id = t.id
            WHERE t.status IN ('active', 'periodic') AND t.is_active = 1
            GROUP BY t.id
        """).fetchall()
        total = sum(r["unpaid"] or 0 for r in rows)
        return total
    finally:
        if close_db:
            db.close()


def get_tenancy_summary(tenancy_id):
    """Get financial summary for a tenancy."""
    db = get_dict_db()
    try:
        tenancy = db.execute("SELECT * FROM tenancies WHERE id = ?", [tenancy_id]).fetchone()
        if not tenancy:
            return None

        charges = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total, COALESCE(SUM(CASE WHEN paid THEN amount ELSE 0 END), 0) AS paid_total FROM rent_charges WHERE tenancy_id = ?",
            [tenancy_id]
        ).fetchone()

        transactions = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM transactions WHERE tenancy_id = ?",
            [tenancy_id]
        ).fetchone()

        deposits = db.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total FROM deposits WHERE tenancy_id = ?",
            [tenancy_id]
        ).fetchone()

        return {
            "tenancy": tenancy,
            "charges": charges,
            "transactions": transactions,
            "deposits": deposits,
        }
    finally:
        db.close()
