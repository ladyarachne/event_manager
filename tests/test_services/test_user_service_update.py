import pytest
from uuid import uuid4
from app.services.user_service import UserService
from app.models.user_model import User, UserRole
from app.utils.security import hash_password, verify_password

@pytest.mark.asyncio
async def test_update_user_with_model_dump(db_session):
    """Test that the update method correctly uses model_dump instead of dict."""
    # Create a test user
    user = User(
        nickname="test_update_user",
        email="test_update@example.com",
        first_name="Test",
        last_name="User",
        hashed_password=hash_password("Password123!"),
        role=UserRole.AUTHENTICATED,
        email_verified=True
    )
    db_session.add(user)
    await db_session.commit()
    
    # Update the user with new data
    update_data = {
        "first_name": "Updated",
        "last_name": "Name",
        "bio": "This is an updated bio."
    }
    
    updated_user = await UserService.update(db_session, user.id, update_data)
    
    # Verify the update was successful
    assert updated_user is not None
    assert updated_user.first_name == "Updated"
    assert updated_user.last_name == "Name"
    assert updated_user.bio == "This is an updated bio."
    
    # Verify that other fields were not changed
    assert updated_user.email == "test_update@example.com"
    assert updated_user.nickname == "test_update_user"
    assert updated_user.email_verified is True

@pytest.mark.asyncio
async def test_update_user_with_password(db_session):
    """Test that the update method correctly handles password updates."""
    # Create a test user
    original_password = "Password123!"
    user = User(
        nickname="test_password_update",
        email="test_password@example.com",
        hashed_password=hash_password(original_password),
        role=UserRole.AUTHENTICATED,
        email_verified=True
    )
    db_session.add(user)
    await db_session.commit()
    
    # Update the user's password
    new_password = "NewPassword456!"
    update_data = {
        "password": new_password
    }
    
    updated_user = await UserService.update(db_session, user.id, update_data)
    
    # Verify the password was updated
    assert updated_user is not None
    assert verify_password(new_password, updated_user.hashed_password) is True
    assert verify_password(original_password, updated_user.hashed_password) is False
