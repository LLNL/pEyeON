from pydantic import BaseModel, EmailStr

class User(BaseModel):
    username: str
    email: EmailStr | None = None
    fullname: str | None = None

class CreateUser(User):
    password: str

class UserInDB(User):
    hashed_password: str
    disabled: bool
    admin: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None