import yaml
import os
import shutil
import jwt
import uvicorn
from src.api import userModel

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, APIRouter, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse

from datetime import timedelta
from typing import Annotated

from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()
#defined in .env ; used for encrypting / hashing functions
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app=FastAPI()

# #Load openai yaml
# with open("./swagger.yml", "r") as api_doc:
#     openai_schema=yaml.safe_load(api_doc)

# #set schema
# app.openapi_schema=openai_schema


#router for api
api_router = APIRouter(prefix="/api")

async def get_current_user(token:str = Depends(oauth2_scheme)):
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
        payload=jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")#key to encode inside jwt token
        if username is None:
            raise cred_exception
        token_data=userModel.TokenData(username=username)
    except InvalidTokenError:
        raise cred_exception
    
    user=userModel.get_user(userModel.fake_users_db, username=token_data.username)
    if user is None:
        raise cred_exception
    
    return user

async def get_current_active_user(current_user: userModel.UserInDB=Depends(get_current_user)):
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
    
@app.post("/token", response_model=userModel.Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> userModel.Token:
    '''
    used to sign in and get a token
    '''
    user = userModel.authenticate_user(userModel.fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = userModel.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token":access_token, "token_type":"bearer"}


@api_router.get("/")
async def api_root():
    return {"message": "Upload your zip files at /api/upload/"}

@api_router.post("/upload")
async def upload_file(current_user: userModel.User = Depends(get_current_active_user), file: UploadFile=File(...)):
    '''
    test command 
    curl -X POST "http://127.0.0.1:8080/api/upload" -F "file=@./test.json"
    '''
    # token=await login(form_data)

    # if not token:
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="Not Authenticated",
    #         headers={"WWW-Authenticate": "Bearer"},
    #     )

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
           
    return {"filename": file.filename, "status": "uploaded", "Owner": current_user}


# if __name__=="__main__":
#     uvicorn.run("src.api.main", host="127.0.0.1", port=8080)

app.include_router(api_router)