#!/usr/bin/env python3

from random import randint, choice as rc
from faker import Faker

from app import app
from models import db, Recipe, User

fake = Faker()

with app.app_context():

    print("Deleting all records...")
    Recipe.query.delete()
    User.query.delete()

    print("Creating users...")
    users = []
    usernames = set()

    for i in range(20):
        username = fake.first_name()
        while username in usernames:
            username = fake.first_name()
        usernames.add(username)

        user = User(
            username=username,
            bio=fake.paragraph(nb_sentences=3),
            image_url=fake.image_url()  
        )

       
        user.password_hash = f"{username.lower()}123"

        users.append(user)

    db.session.add_all(users)

    print("Creating recipes...")
    recipes = []
    for i in range(100):
        instructions = fake.paragraph(nb_sentences=10)
        
        recipe = Recipe(
            title=fake.sentence(nb_words=5),
            instructions=instructions,
            minutes_to_complete=randint(10, 60),
            user=rc(users) 
        )

        recipes.append(recipe)

    db.session.add_all(recipes)

    db.session.commit()
    print("Seeding complete.")
