from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import List, Optional
import hashlib
import secrets
import os

# Directory to store images
IMAGE_UPLOAD_DIR = "./image_data"
os.makedirs(IMAGE_UPLOAD_DIR, exist_ok=True)  # Ensure the directory

# FastAPI app instance
app = FastAPI()

# Initialize SQLite database with SQLAlchemy
DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Models using SQLAlchemy ---
class User(Base):
    __tablename__ = "auth"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    token = Column(String, nullable=True)


class EventData(Base):
    __tablename__ = "data"
    id = Column(Integer, primary_key=True, index=True)
    date = Column(String, nullable=False)
    time = Column(String, nullable=False)
    description = Column(String, nullable=False)
    image_file_path = Column(String, nullable=False)


# Create database tables
Base.metadata.create_all(bind=engine)


# --- Pydantic Models ---
class AuthModel(BaseModel):
    username: str
    password: str


class TokenModel(BaseModel):
    token: str


class DataModel(BaseModel):
    id: Optional[int] = None
    date: str
    time: str
    description: str
    image_file_path: str


# Utility function to hash passwords
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Utility function to authenticate token
def authenticate_token(token: str, db: Session):
    user = db.query(User).filter(User.token == token).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


# --- Authentication Endpoints ---
@app.post("/register")
def register(user: AuthModel, db: Session = Depends(get_db)):
    hashed_password = hash_password(user.password)
    new_user = User(username=user.username, password=hashed_password)
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except:
        db.rollback()
        raise HTTPException(status_code=400, detail="Username already exists")
    return {"message": "User registered successfully"}


@app.post("/login", response_model=TokenModel)
def login(user: AuthModel, db: Session = Depends(get_db)):
    hashed_password = hash_password(user.password)
    user_record = db.query(User).filter(User.username == user.username, User.password == hashed_password).first()
    if not user_record:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Generate a new token and save it
    token = secrets.token_hex(16)
    user_record.token = token
    db.commit()
    return {"token": token}


# --- CRUD Endpoints ---
@app.post("/data", response_model=DataModel)
def create_data(data: DataModel, token: str, db: Session = Depends(get_db)):
    user = authenticate_token(token, db)
    new_data = EventData(date=data.date, time=data.time, description=data.description,
                         image_file_path=data.image_file_path)
    db.add(new_data)
    db.commit()
    db.refresh(new_data)
    return DataModel.from_orm(new_data)


@app.get("/data", response_model=List[DataModel])
def read_data(token: str, db: Session = Depends(get_db)):
    user = authenticate_token(token, db)
    data_objects = db.query(EventData).all()
    return [DataModel.from_orm(data) for data in data_objects]


@app.put("/data/{data_id}", response_model=DataModel)
def update_data(data_id: int, updated_data: DataModel, token: str, db: Session = Depends(get_db)):
    user = authenticate_token(token, db)
    data_object = db.query(EventData).filter(EventData.id == data_id).first()
    if not data_object:
        raise HTTPException(status_code=404, detail="Data not found")

    # Update fields
    data_object.date = updated_data.date
    data_object.time = updated_data.time
    data_object.description = updated_data.description
    data_object.image_file_path = updated_data.image_file_path
    db.commit()
    db.refresh(data_object)
    return DataModel.from_orm(data_object)


@app.delete("/data/{data_id}")
def delete_data(data_id: int, token: str, db: Session = Depends(get_db)):
    user = authenticate_token(token, db)
    data_object = db.query(EventData).filter(EventData.id == data_id).first()
    if not data_object:
        raise HTTPException(status_code=404, detail="Data not found")

    db.delete(data_object)
    db.commit()
    return {"message": "Data deleted successfully"}

# --- Image Upload Endpoint ---
@app.post("/upload-image/")
def upload_image(file: UploadFile = File(...)):
    # Check if the uploaded file is an image
    if not file.filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
        raise HTTPException(status_code=400, detail="Invalid file type. Only image files are allowed.")

    file_path = os.path.join(IMAGE_UPLOAD_DIR, file.filename)
    if os.path.exists(file_path):  # Prevent overwriting stored images
        raise HTTPException(status_code=400, detail="File already exists.")

    with open(file_path, "wb") as f:
        f.write(file.file.read())

    return {"message": "Image uploaded successfully", "filename": file.filename}


# --- Retrieve List of Images ---
@app.get("/images/", response_model=List[str])
def list_images():
    # List all files in the image directory
    images = os.listdir(IMAGE_UPLOAD_DIR)
    if not images:
        raise HTTPException(status_code=404, detail="No images found.")
    return images


# --- Retrieve a Specific Image ---
@app.get("/images/{filename}")
def get_image(filename: str):
    file_path = os.path.join(IMAGE_UPLOAD_DIR, filename)
    print(file_path)

    if not os.path.exists(file_path):  # Check if the image exists
        raise HTTPException(status_code=404, detail="Image not found.")

    return FileResponse(file_path, media_type="image/jpeg", filename=filename)

