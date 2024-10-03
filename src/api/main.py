import os
import shutil
import jwt
# import uvicorn

from src.api import userModel, database, security

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, APIRouter, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse

from datetime import timedelta
from typing import Annotated, List

from jwt.exceptions import InvalidTokenError

from sqlalchemy.orm import Session

# Dependency to get the session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

app=FastAPI()

#router for api
api_router = APIRouter(prefix="/api")

async def get_current_user(token:Annotated[str, Depends(security.oauth2_scheme)], db: db_dependency):
    '''
    parses oauth scheme and pulls out token, username
    verifies user is in db
    '''
    cred_exception=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
        )
    
    try:
        payload=jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        username: str = payload.get("sub")#key to encode inside jwt token
        if username is None:
            raise cred_exception
        token_data=userModel.TokenData(username=username)
    except InvalidTokenError:
        raise cred_exception
    
    user=database.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise cred_exception
    
    return user

async def get_current_active_user(current_user: Annotated[userModel.UserInDB, Depends(get_current_user)]):
    '''
    Check user is enabled
    '''
    if current_user.disabled:
        raise HTTPException(
            status_code=400,
            detail="Invalid User"
        )
    return current_user

@app.get("/")
async def root():
    return RedirectResponse(url="/api")

@app.post("/register/", status_code=status.HTTP_201_CREATED)
def register(user: userModel.CreateUser, db: db_dependency):
    existing_user = database.get_user_by_username(db, user.username)
    existing_email = database.get_user_by_email(db, user.email)
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    new_user = database.create_user(db, user.username, user.password, user.fullname, user.email)
    return {"id": new_user.id, "username": new_user.username, "full_name": new_user.fullname, "email": new_user.email}


@app.get("/users/", response_model=List[userModel.UserInDB])
def read_users(db: db_dependency):
    '''
    returns all users and data in the db
    '''
    users = database.get_all_users(db)
    return users

@app.post("/token", response_model=userModel.Token)
async def login(db: db_dependency, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> userModel.Token:
    '''
    used to sign in and get a token
    '''
    user = security.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    token=userModel.Token(access_token=access_token, token_type="bearer")
    return token


@api_router.get("/")
async def api_root():
    return {"message": "Register at /register, Upload your zip files at /api/upload/"}

@api_router.post("/upload")
async def upload_file(current_user: userModel.User = Depends(get_current_active_user), file: UploadFile=File(...)):
    '''
    upload route for json, duckdb, tar files 
    '''
    allowed_extensions = {'.json', '.duckdb', '.tar'}

    #spit and ignore filename
    _, file_extension = os.path.splitext(file.filename)

    if file_extension not in allowed_extensions:
        raise HTTPException(status_code=400, detail="File must be a JSON, DuckDB, or TAR file.")
    
    #where to write the file
    storage_dir="src/api/storage_dir/"
    write_path=os.path.join(storage_dir, file.filename)

    with open(write_path, "wb") as buffer:
           shutil.copyfileobj(file.file, buffer)
           
    return {
        "filename": file.filename, 
        "status": "uploaded", 
        "Owner": {
            "current user":current_user.username, 
            "email":current_user.email, 
            "full name": current_user.fullname
            }
        }


# if __name__=="__main__":
#     uvicorn.run("src.api.main", host="127.0.0.1", port=8080)

app.include_router(api_router)