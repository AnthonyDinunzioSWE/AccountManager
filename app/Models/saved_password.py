from ..Instances.instances import db
from datetime import datetime
import uuid


class SavedPassword(db.Model):
    id = db.Column(db.UUID, primary_key=True, default=uuid.uuid4)
    type = db.Column(db.String(50), nullable=False)  # e.g., 'email', 'password', 'username'
    value = db.Column(db.String(256), nullable=False)
    hashed_value = db.Column(db.String(256), nullable=False)  # Hashed value for security
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user_id = db.Column(db.UUID, db.ForeignKey('user.id'), nullable=False)

    # Add a property to track whether the password is unhashed
    is_unhashed = False