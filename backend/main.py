from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
import shutil

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
import os
from typing import List, Optional
import logging
from dotenv import load_dotenv

from database import get_db, engine
from models import Base, User, Task, Event, Puzzle
from schemas import (
    UserCreate, UserLogin, UserResponse, UserUpdate,
    TaskCreate, TaskUpdate, TaskResponse,
    EventCreate, EventUpdate, EventResponse,
    PuzzleCreate, PuzzleUpdate, PuzzleResponse,
    Token, TokenData, TaskExtractionRequest
)
from auth import (
    create_access_token, get_current_user, 
    get_password_hash, verify_password,
    ADMIN_EMAIL
)
from task_extractor import extract_tasks_from_text, extract_tasks_from_audio
from calendar_integration import GoogleCalendarService

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Chess Club Task Management API",
    description="Backend API for Chess Club task management and event organization",
    version="1.0.0"
)

# Security & Middleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Trusted Host (Prevent Host Header Attacks)
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

# CORS middleware
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
origins = [FRONTEND_URL]
if os.getenv("ENVIRONMENT", "development") != "production":
    origins.extend(["http://localhost:5173", "http://localhost:8000"])


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Initialize Google Calendar service
calendar_service = GoogleCalendarService()

@app.get("/ping")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.post("/auth/signup", response_model=UserResponse)
async def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    """User signup endpoint"""
    try:
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create new user
        hashed_password = get_password_hash(user_data.password)
        db_user = User(
            email=user_data.email,
            username=user_data.username,
            hashed_password=hashed_password,
            full_name=user_data.full_name,
            department=user_data.department,
            year=user_data.year
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"New user registered: {db_user.email}")
        return db_user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in user signup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
async def login(request: Request, user_credentials: UserLogin, db: Session = Depends(get_db)):
    """User login endpoint"""
    try:
        # Verify user credentials
        user = db.query(User).filter(User.email == user_credentials.email).first()
        if not user or not verify_password(user_credentials.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Create access token
        access_token = create_access_token(data={"sub": user.email})
        
        logger.info(f"User logged in: {user.email}")
        return {"access_token": access_token, "token_type": "bearer"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in user login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/auth/verify-token")
async def verify_token_endpoint(current_user: User = Depends(get_current_user)):
    """Verify the current user's token and return user details"""
    return {"status": "ok", "user": UserResponse.from_orm(current_user)}

# ==================== TASK MANAGEMENT ENDPOINTS ====================

@app.post("/tasks", response_model=TaskResponse)
async def create_task(
    task_data: TaskCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new task"""
    try:
        db_task = Task(
            **task_data.dict(),
            user_id=current_user.id,
            created_at=datetime.utcnow()
        )
        
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
        
        # Optional: Sync with Google Calendar if user has linked account
        if current_user.google_calendar_token:
            try:
                calendar_service.create_event(
                    token=current_user.google_calendar_token,
                    title=db_task.task_description,
                    start_time=db_task.deadline,
                    end_time=db_task.deadline + timedelta(hours=1)
                )
            except Exception as e:
                logger.warning(f"Failed to sync with Google Calendar: {str(e)}")
        
        logger.info(f"Task created for user {current_user.email}: {db_task.task_description}")
        return db_task
        
    except Exception as e:
        logger.error(f"Error creating task: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/tasks", response_model=List[TaskResponse])
async def get_tasks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    status_filter: Optional[str] = None
):
    """Get all tasks for the current user"""
    try:
        query = db.query(Task).filter(Task.user_id == current_user.id)
        
        if status_filter:
            query = query.filter(Task.status == status_filter)
        
        tasks = query.order_by(Task.deadline.asc()).all()
        return tasks
        
    except Exception as e:
        logger.error(f"Error fetching tasks: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(
    task_id: int,
    task_data: TaskUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update an existing task"""
    try:
        db_task = db.query(Task).filter(
            Task.id == task_id,
            Task.user_id == current_user.id
        ).first()
        
        if not db_task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        # Update task fields
        for field, value in task_data.dict(exclude_unset=True).items():
            setattr(db_task, field, value)
        
        db.commit()
        db.refresh(db_task)
        
        logger.info(f"Task updated for user {current_user.email}: {db_task.task_description}")
        return db_task
        
    except Exception as e:
        logger.error(f"Error updating task: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.delete("/tasks/{task_id}")
async def delete_task(
    task_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a task"""
    try:
        db_task = db.query(Task).filter(
            Task.id == task_id,
            Task.user_id == current_user.id
        ).first()
        
        if not db_task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )
        
        db.delete(db_task)
        db.commit()
        
        logger.info(f"Task deleted for user {current_user.email}: {db_task.task_description}")
        return {"message": "Task deleted successfully"}
        
    except Exception as e:
        logger.error(f"Error deleting task: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# ==================== TASK EXTRACTION ENDPOINTS ====================

@app.post("/extract-tasks/text")
async def extract_tasks_from_text_input(
    request: TaskExtractionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Extract tasks from text input using NLP"""
    try:
        # Extract tasks using NLP
        extracted_tasks = extract_tasks_from_text(request.text)
        
        # Save extracted tasks to database
        saved_tasks = []
        for task_info in extracted_tasks:
            db_task = Task(
                task_description=task_info["description"],
                deadline=task_info["deadline"],
                status="pending",
                user_id=current_user.id,
                created_at=datetime.utcnow()
            )
            db.add(db_task)
            saved_tasks.append(db_task)
        
        db.commit()
        
        logger.info(f"Extracted {len(saved_tasks)} tasks from text for user {current_user.email}")
        return {
            "message": f"Successfully extracted {len(saved_tasks)} tasks",
            "extracted_tasks": extracted_tasks,
            "saved_tasks": [{"id": t.id, "description": t.task_description, "deadline": t.deadline} for t in saved_tasks]
        }
        
    except Exception as e:
        logger.error(f"Error extracting tasks from text: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error extracting tasks from text"
        )

@app.post("/extract-tasks/audio")
async def extract_tasks_from_audio(
    audio_file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Extract tasks from audio input using Whisper + NLP"""
    try:
        # Validate file type
        if not audio_file.content_type.startswith("audio/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an audio file"
            )
        
        # Extract text from audio using Whisper
        text = await extract_tasks_from_audio(audio_file)
        
        # Extract tasks from transcribed text
        extracted_tasks = extract_tasks_from_text(text)
        
        # Save extracted tasks to database
        saved_tasks = []
        for task_info in extracted_tasks:
            db_task = Task(
                task_description=task_info["description"],
                deadline=task_info["deadline"],
                status="pending",
                user_id=current_user.id,
                created_at=datetime.utcnow()
            )
            db.add(db_task)
            saved_tasks.append(db_task)
        
        db.commit()
        
        logger.info(f"Extracted {len(saved_tasks)} tasks from audio for user {current_user.email}")
        return {
            "message": f"Successfully extracted {len(saved_tasks)} tasks from audio",
            "transcribed_text": text,
            "extracted_tasks": extracted_tasks,
            "saved_tasks": [{"id": t.id, "description": t.task_description, "deadline": t.deadline} for t in saved_tasks]
        }
        
    except Exception as e:
        logger.error(f"Error extracting tasks from audio: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error extracting tasks from audio"
        )







@app.post("/events", response_model=EventResponse)
async def create_event(
    event_data: EventCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new event (Admin only)"""
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create events"
        )
    
    try:
        logger.info(f"Creating event with data: title={event_data.title}, date={event_data.date}, time={event_data.time}")
        
        db_event = Event(
            title=event_data.title,
            description=event_data.description,
            date=event_data.date,
            time=event_data.time,
            venue=event_data.venue,
            event_type=event_data.event_type,
            image_url=event_data.image_url,
            max_participants=event_data.max_participants,
            registration_required=event_data.registration_required if event_data.registration_required is not None else False,
            registration_link=event_data.registration_link,
            is_active=True,  # Explicitly set default
            created_by=current_user.id
        )
        
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
        
        logger.info(f"Event created by admin {current_user.email}: {db_event.title}")
        return db_event
        
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating event: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error during event creation: {str(e)}"
        )

@app.get("/events", response_model=List[EventResponse])
async def get_events(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """Get all events (public endpoint) with pagination"""
    try:
        events = db.query(Event).order_by(Event.date.desc()).offset(skip).limit(limit).all()
        return events
        
    except Exception as e:
        logger.error(f"Error fetching events: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.put("/events/{event_id}", response_model=EventResponse)
async def update_event(
    event_id: int,
    event_data: EventUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update an event (Admin only)"""
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can update events"
        )
    
    try:
        db_event = db.query(Event).filter(Event.id == event_id).first()
        
        if not db_event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Event not found"
            )
        
        # Update event fields
        for field, value in event_data.dict(exclude_unset=True).items():
            setattr(db_event, field, value)
        
        db.commit()
        db.refresh(db_event)
        
        logger.info(f"Event updated by admin {current_user.email}: {db_event.title}")
        return db_event
        
    except Exception as e:
        logger.error(f"Error updating event: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.delete("/events/{event_id}")
async def delete_event(
    event_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an event (Admin only)"""
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can delete events"
        )
    
    try:
        db_event = db.query(Event).filter(Event.id == event_id).first()
        
        if not db_event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Event not found"
            )
        
        db.delete(db_event)
        db.commit()
        
        logger.info(f"Event deleted by admin {current_user.email}: {db_event.title}")
        return {"message": "Event deleted successfully"}
        
    except Exception as e:
        logger.error(f"Error deleting event: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

UPLOAD_DIRECTORY = "../public/event-images"

@app.post("/events/{event_id}/upload-image", response_model=EventResponse)
async def upload_event_image(
    event_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload an image for an event (Admin only)"""
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can upload images"
        )

    db_event = db.query(Event).filter(Event.id == event_id).first()
    if not db_event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Create upload directory if it doesn't exist
    os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

    # Generate a safe filename
    file_extension = os.path.splitext(file.filename)[1]
    safe_filename = f"{event_id}_{datetime.utcnow().timestamp()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIRECTORY, safe_filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    finally:
        file.file.close()

    # Update the event with the image URL
    # The URL should be relative to the public directory of the frontend
    db_event.image_url = f"/event-images/{safe_filename}"
    db.commit()
    db.refresh(db_event)

    logger.info(f"Image uploaded for event {event_id} by admin {current_user.email}")
    return db_event

# ==================== PUZZLE ENDPOINTS ====================

@app.post("/puzzles", response_model=PuzzleResponse)
async def create_puzzle(
    puzzle_data: PuzzleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new puzzle (Admin only)"""
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can create puzzles"
        )
    
    try:
        db_puzzle = Puzzle(
            **puzzle_data.dict(),
            created_at=datetime.utcnow()
        )
        
        db.add(db_puzzle)
        db.commit()
        db.refresh(db_puzzle)
        
        logger.info(f"Puzzle created by admin {current_user.email}: {db_puzzle.title}")
        return db_puzzle
        
    except Exception as e:
        logger.error(f"Error creating puzzle: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/puzzles", response_model=List[PuzzleResponse])
async def get_puzzles(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    """Get all puzzles (public endpoint)"""
    try:
        puzzles = db.query(Puzzle).order_by(Puzzle.created_at.desc()).offset(skip).limit(limit).all()
        return puzzles
        
    except Exception as e:
        logger.error(f"Error fetching puzzles: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.put("/puzzles/{puzzle_id}", response_model=PuzzleResponse)
async def update_puzzle(
    puzzle_id: int,
    puzzle_data: PuzzleUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update a puzzle (Admin only)"""
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can update puzzles"
        )
    
    try:
        db_puzzle = db.query(Puzzle).filter(Puzzle.id == puzzle_id).first()
        
        if not db_puzzle:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Puzzle not found"
            )
        
        # Update puzzle fields
        for field, value in puzzle_data.dict(exclude_unset=True).items():
            setattr(db_puzzle, field, value)
        
        db.commit()
        db.refresh(db_puzzle)
        
        logger.info(f"Puzzle updated by admin {current_user.email}: {db_puzzle.title}")
        return db_puzzle
        
    except Exception as e:
        logger.error(f"Error updating puzzle: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.delete("/puzzles/{puzzle_id}")
async def delete_puzzle(
    puzzle_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a puzzle (Admin only)"""
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can delete puzzles"
        )
    
    try:
        db_puzzle = db.query(Puzzle).filter(Puzzle.id == puzzle_id).first()
        
        if not db_puzzle:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Puzzle not found"
            )
        
        db.delete(db_puzzle)
        db.commit()
        
        logger.info(f"Puzzle deleted by admin {current_user.email}: {db_puzzle.title}")
        return {"message": "Puzzle deleted successfully"}
        
    except Exception as e:
        logger.error(f"Error deleting puzzle: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


# ==================== BOT ENDPOINTS ====================
from bot_manager import start_bot, stop_bot, get_status, update_config, get_config
from schemas import BotConfig

@app.get("/bot/status")
async def bot_status(current_user: User = Depends(get_current_user)):
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin only")
    return get_status()

@app.post("/bot/start")
async def bot_start(current_user: User = Depends(get_current_user)):
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin only")
    return start_bot()

@app.post("/bot/stop")
async def bot_stop(current_user: User = Depends(get_current_user)):
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin only")
    return stop_bot()

@app.get("/bot/config")
async def bot_get_config(current_user: User = Depends(get_current_user)):
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin only")
    cfg = get_config()
    # Mask token for security in UI
    if 'token' in cfg:
        cfg['token'] = "********" 
    return cfg

@app.post("/bot/config")
async def bot_update_config(config: BotConfig, current_user: User = Depends(get_current_user)):
    if current_user.email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin only")
    return update_config(config.token, config.engine)


# ==================== USER PROFILE ENDPOINTS ====================

@app.get("/profile", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    return current_user

@app.put("/profile", response_model=UserResponse)
async def update_profile(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user profile"""
    try:
        # Update user fields
        for field, value in user_data.dict(exclude_unset=True).items():
            if field == "password":
                value = get_password_hash(value)
                setattr(current_user, "hashed_password", value)
            else:
                setattr(current_user, field, value)
        
        db.commit()
        db.refresh(current_user)
        
        logger.info(f"Profile updated for user {current_user.email}")
        return current_user
        
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
