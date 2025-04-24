from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List, Set
from datetime import datetime
from enum import Enum
import uuid
import re

from app.utils.nickname_gen import generate_nickname

# List of allowed email domains
ALLOWED_EMAIL_DOMAINS: Set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", 
    "example.com", "company.com", "university.edu", "organization.org"
}

def validate_email_domain(email: str) -> str:
    """
    Validate that the email domain is in the allowed list.
    """
    if not email or '@' not in email:
        raise ValueError("Invalid email format")
    
    domain = email.split('@')[-1].lower()
    if domain not in ALLOWED_EMAIL_DOMAINS:
        raise ValueError(f"Email domain '{domain}' is not allowed. Please use one of the allowed domains.")
    
    return email

def validate_password(password: str) -> str:
    """
    Validate password complexity requirements:
    - Minimum length of 8 characters
    - Maximum length of 100 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if len(password) > 100:
        raise ValueError("Password must be at most 100 characters long")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r'[0-9]', password):
        raise ValueError("Password must contain at least one number")
    if not re.search(r'[^A-Za-z0-9]', password):
        raise ValueError("Password must contain at least one special character")
    return password

class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

def validate_profile_picture_url(url: Optional[str]) -> Optional[str]:
    """
    Validate that the profile picture URL points to a valid image format.
    Supported formats: jpg, jpeg, png, gif, webp, svg
    """
    if url is None:
        return url
    
    # First validate that it's a valid URL
    url = validate_url(url)
    
    # Then check if it has a valid image extension
    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg']
    has_valid_extension = any(url.lower().endswith(ext) for ext in valid_extensions)
    
    # Also check for URLs that might have query parameters after the extension
    if not has_valid_extension:
        url_path = url.split('?')[0]  # Remove query parameters
        has_valid_extension = any(url_path.lower().endswith(ext) for ext in valid_extensions)
    
    if not has_valid_extension:
        raise ValueError('Profile picture URL must point to a valid image format (jpg, jpeg, png, gif, webp, svg)')
    
    return url

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    
    _validate_email_domain = validator('email', allow_reuse=True)(validate_email_domain)
    nickname: Optional[str] = Field(None, min_length=3, max_length=50, pattern=r'^[\w-]+$', example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, max_length=500, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    _validate_linkedin_github_urls = validator('linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
    _validate_profile_picture = validator('profile_picture_url', pre=True, allow_reuse=True)(validate_profile_picture_url)
 
    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., min_length=8, max_length=100, example="Secure*1234")
    
    _validate_password = validator('password', allow_reuse=True)(validate_password)

class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, max_length=50, pattern=r'^[\w-]+$', example="john_doe123")
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, max_length=500, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    password: Optional[str] = Field(None, min_length=8, max_length=100, example="Secure*1234")
    
    _validate_password = validator('password', allow_reuse=True)(validate_password)

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, max_length=50, pattern=r'^[\w-]+$', example=generate_nickname())    
    is_professional: Optional[bool] = Field(default=False, example=True)

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(), "nickname": generate_nickname(), "email": "john.doe@example.com",
        "first_name": "John", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "last_name": "Doe", 
        "profile_picture_url": "https://example.com/profiles/john.jpg", 
        "linkedin_profile_url": "https://linkedin.com/in/johndoe", 
        "github_profile_url": "https://github.com/johndoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
