import os
from src.api import security
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()
db = os.getenv("DATABASE_URL")

engine = create_engine(db,echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    fullname= Column(String)
    username = Column(String, unique=True, index=True)
    email=Column(String, unique=True, index=True)
    hashed_password = Column(String)
    disabled=Column(Boolean, default=False)
    admin=Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)
    
#create a new user in the database
def create_user(db: Session, username: str, password: str, fullname: str, email: str):
    hashed_password = security.hash_password(password)
    db_user = User(username=username, hashed_password=hashed_password, fullname=fullname, email=email)
    db.add(db_user)
    db.commit()
    db.refresh(db_user) #ensures the db_user object has the most up to date db info
    return db_user

def admin_seed(db: Session):
    '''
    Create a default admin user ; called by on init db
    '''
    hashed_password=security.hash_password(security.ADMIN_PWD)
    admin_user=User(username="admin", hashed_password=hashed_password, fullname="Admin", email="admin@admin.com", admin=True)
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_all_users(db: Session):
    return db.query(User).all()
