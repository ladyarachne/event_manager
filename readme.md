# Event Manager API

This repository contains a secure, robust REST API that supports JWT token-based OAuth2 authentication. The API serves as the backbone of a user management system and will eventually expand to include features for event management and registration.

## Resolved Issues

The following issues have been identified, documented, and resolved:

1. **Username Validation**: Added maximum length constraint to nickname field to prevent excessively long nicknames. [Issue #1](https://github.com/yourusername/event_manager/issues/1)
   - Added max_length=50 validation to the nickname field in UserBase schema
   - Added test case for validating that nicknames longer than 50 characters are invalid

2. **Password Validation**: Implemented comprehensive password validation with complexity requirements. [Issue #2](https://github.com/yourusername/event_manager/issues/2)
   - Added validation for minimum length (8 characters)
   - Added validation for maximum length (100 characters)
   - Added validation for requiring uppercase letters
   - Added validation for requiring lowercase letters
   - Added validation for requiring numbers
   - Added validation for requiring special characters
   - Added test cases for valid and invalid passwords

3. **Profile Field Edge Cases**: Fixed issues with profile field validation and handling. [Issue #3](https://github.com/yourusername/event_manager/issues/3)
   - Added max_length=500 validation to the bio field in UserBase schema
   - Fixed duplicate fields in UserResponse schema
   - Fixed duplicate fields in UserListResponse example
   - Added test for updating multiple profile fields simultaneously
   - Added test for bio field maximum length validation

4. **Pydantic v2 Compatibility**: Fixed compatibility issues with Pydantic v2. [Issue #6](https://github.com/yourusername/event_manager/issues/6)
   - Updated UserService.update method to use model_dump() instead of dict() for Pydantic v2 compatibility
   - Added tests to verify that the update method works correctly with model_dump()

## Project Image on Docker Hub

[Link to project image on Docker Hub](https://hub.docker.com/yourusername/event_manager)

## Reflection

Working on this assignment has been an invaluable learning experience that has deepened my understanding of both technical aspects and collaborative processes in software development. From a technical standpoint, I gained hands-on experience with FastAPI, SQLAlchemy, and Pydantic, learning how these technologies work together to create a robust REST API. I particularly appreciated how FastAPI leverages Python type hints for automatic validation and documentation generation, making it easier to build and maintain secure APIs.

The process of identifying and resolving issues taught me the importance of thorough testing and validation. By implementing comprehensive validation rules for usernames and passwords, I learned how proper input validation is crucial for maintaining data integrity and security. Working with edge cases in profile field updates highlighted the importance of considering all possible scenarios when designing API endpoints, ensuring that the API behaves predictably regardless of how users interact with it.

From a collaborative perspective, using Git for version control and GitHub for issue tracking provided practical experience with industry-standard tools and workflows. Creating separate branches for each issue, implementing fixes, and merging them back into the main branch reinforced the value of organized, methodical approaches to software development. This workflow not only kept the codebase clean and manageable but also created a clear history of changes that would be invaluable in a team setting. Overall, this assignment has equipped me with practical skills and insights that will be directly applicable in real-world software development projects.
