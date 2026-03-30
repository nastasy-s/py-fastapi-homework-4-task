from fastapi import APIRouter, Depends, status, HTTPException, Request, UploadFile, File, Form
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from datetime import date
from pydantic import ValidationError

from config import get_jwt_auth_manager, get_s3_storage_client
from database import get_db, UserModel, UserProfileModel, UserGroupEnum
from exceptions import BaseSecurityError, S3FileUploadError
from schemas.profiles import ProfileCreateRequestSchema, ProfileResponseSchema
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface

router = APIRouter()


def get_token(request: Request) -> str:
    authorization: str = request.headers.get("Authorization")
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing"
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'"
        )
    return token


async def get_profile_data(
        first_name: str = Form(...),
        last_name: str = Form(...),
        gender: str = Form(...),
        date_of_birth: date = Form(...),
        info: str = Form(...),
        avatar: UploadFile = File(...),
) -> ProfileCreateRequestSchema:
    try:
        return ProfileCreateRequestSchema(
            first_name=first_name,
            last_name=last_name,
            gender=gender,
            date_of_birth=date_of_birth,
            info=info,
            avatar=avatar,
        )
    except ValidationError as e:
        first_error = e.errors()[0]
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=first_error["msg"].replace("Value error, ", "")
        )


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_profile(
        user_id: int,
        token: str = Depends(get_token),
        profile_data: ProfileCreateRequestSchema = Depends(get_profile_data),
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        s3_client: S3StorageInterface = Depends(get_s3_storage_client),
) -> ProfileResponseSchema:

    try:
        decoded = jwt_manager.decode_access_token(token)
        token_user_id = decoded.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    stmt = select(UserModel).where(UserModel.id == token_user_id).options(joinedload(UserModel.group))
    result = await db.execute(stmt)
    requester = result.scalars().first()

    is_admin = requester and requester.group.name == UserGroupEnum.ADMIN
    if token_user_id != user_id and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile."
        )

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active."
        )

    stmt = select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    result = await db.execute(stmt)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile."
        )

    avatar = profile_data.avatar
    extension = avatar.filename.rsplit(".", 1)[-1].lower()
    file_key = f"avatars/{user_id}_avatar.{extension}"
    file_data = await avatar.read()

    try:
        await s3_client.upload_file(file_name=file_key, file_data=file_data)
        avatar_url = await s3_client.get_file_url(file_key)
    except S3FileUploadError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later."
        )

    new_profile = UserProfileModel(
        user_id=user_id,
        first_name=profile_data.first_name,
        last_name=profile_data.last_name,
        gender=profile_data.gender,
        date_of_birth=profile_data.date_of_birth,
        info=profile_data.info,
        avatar=file_key,
    )

    print("BEFORE SAVE file_key:", file_key)
    print("BEFORE SAVE model.avatar:", new_profile.avatar)

    db.add(new_profile)
    await db.commit()
    await db.refresh(new_profile)

    print("AFTER SAVE model.avatar:", new_profile.avatar)

    response = ProfileResponseSchema.model_validate(new_profile)
    response.avatar = avatar_url
    return response
