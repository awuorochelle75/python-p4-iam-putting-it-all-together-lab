from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user', cascade="all, delete-orphan")

    serialize_rules = ('-recipes.user',)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
      
        if '_password_hash' not in kwargs or not kwargs.get('_password_hash'):
            self.password_hash = "default123"

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes cannot be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    def __repr__(self):
        return f"<User {self.username}>"


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    serialize_rules = ('-user.recipes',)

    @validates('instructions')
    def validate_instructions(self, key, value):
        if not value or len(value) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value

    def __repr__(self):
        return f"<Recipe {self.title}>"
