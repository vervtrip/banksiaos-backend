"""
Banksia OS — Notifications service layer.
User notifications, my-updates feed, and notification management.
"""
from datetime import datetime
from banksia_os_db import get_dict_db
from services.db_service import json_success


def create_notification(username, message, link=None):
    """Create a notification for a user."""
    try:
        db = get_dict_db()
        db.execute(
            "INSERT INTO notifications (username, message, link, created_at, is_read) VALUES (?, ?, ?, datetime('now'), 0)",
            [username, message, link]
        )
        db.commit()
        db.close()
    except Exception:
        pass


def get_user_notifications(username, limit=50, unread_only=False):
    """Get notifications for a user."""
    db = get_dict_db()
    try:
        if unread_only:
            rows = db.execute(
                "SELECT * FROM notifications WHERE username = ? AND is_read = 0 ORDER BY created_at DESC LIMIT ?",
                [username, limit]
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM notifications WHERE username = ? ORDER BY created_at DESC LIMIT ?",
                [username, limit]
            ).fetchall()
        return rows
    finally:
        db.close()


def get_my_updates(username, limit=50):
    """Get personalised update feed for a user."""
    db = get_dict_db()
    try:
        # Activity log entries by or about this user
        activity = db.execute("""
            SELECT * FROM activity_log
            WHERE user_name = ? OR entity_id IN (
                SELECT id FROM tenancies WHERE id IN (
                    SELECT tenancy_id FROM tenancy_tenants WHERE tenant_id IN (
                        SELECT id FROM tenants WHERE email = ?
                    )
                )
            )
            ORDER BY created_at DESC LIMIT ?
        """, [username, username, limit]).fetchall()

        # Recent notifications
        notifications = db.execute(
            "SELECT * FROM notifications WHERE username = ? ORDER BY created_at DESC LIMIT 20",
            [username]
        ).fetchall()

        # Recent comments mentioning this user
        comments = db.execute("""
            SELECT c.*, t.subject FROM comments c
            LEFT JOIN threads t ON t.id = c.thread_id
            WHERE c.body LIKE ? ORDER BY c.created_at DESC LIMIT 20
        """, [f"%@{username}%"]).fetchall()

        return {
            "activity": activity,
            "notifications": notifications,
            "mentions": comments,
        }
    finally:
        db.close()
