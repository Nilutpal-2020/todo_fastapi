from fastapi import APIRouter, Depends, HTTPException, Path
from models import Users
from database import SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
from starlette import status
from pydantic import BaseModel, Field
from .auth import get_current_user
from passlib.context import CryptContext

router = APIRouter(
    prefix="/users",
    tags=['users']
)

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

class UserVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.get('/', status_code=status.HTTP_200_OK)
async def get_user_details(user: user_dependency,
                   db: db_dependency):
    if user is None:
        raise HTTPException(status_code=404, detail="User details not found")
    return db.query(Users).filter(Users.id == user.get('id')).first()

@router.put('/change_password', status_code=status.HTTP_204_NO_CONTENT)
async def change_user_password(user: user_dependency,
                               db: db_dependency,
                               user_verification: UserVerification):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()

    if not bcrypt_context.verify(user_verification.password, user_model.hashed_password):
        raise HTTPException(status_code=401, detail="Error on password change")
    if user_model is None:
        raise HTTPException(status_code=404, detail="User not found!")

    user_model.hashed_password = bcrypt_context.hash(user_verification.new_password)

    db.add(user_model)
    db.commit()