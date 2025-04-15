from ..Instances.instances import db
from flask_login import UserMixin
from datetime import datetime
import uuid


class User(db.Model, UserMixin):
    id = db.Column(db.UUID, primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    saved_passwords = db.relationship('SavedPassword', backref='owner', lazy=True)  # Renamed backref to 'owner'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.email}>'

    def get_id(self):
        return self.id