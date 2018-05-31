import sys

from sqlalchemy import Column, ForeignKey, Integer, String

import mysql.connector

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import relationship

from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    """ User class
    """
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(80), nullable=False)
    username = Column(String(80), nullable=False)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username
        }


class Category(Base):
    """ Categories class
    """
    __tablename__ = 'category'
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }


class CategoryItem(Base):
    """ Items class
    """
    __tablename__ = 'category_item'
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    image = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'description': self.description,
            'image': self.image,
            'category_id': self.category_id,
            'user_id': self.user_id
        }


engine = create_engine('mysql+mysqlconnector://lauwrentius:LAuwrent1us@aa1kczw6kaut3s5.celmatwbtx0m.us-west-2.rds.amazonaws.com/test')
Base.metadata.create_all(engine)
