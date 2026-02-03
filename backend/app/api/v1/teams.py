"""
Teams API endpoints
Manage teams and team members
"""
from fastapi import APIRouter, HTTPException, Depends, status, Query
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from app.core.dependencies import get_current_user, get_supabase_client
from app.core.rbac import (
    Role, Permission, RBACService,
    require_permission, require_role,
    create_team, add_team_member, remove_team_member, get_user_teams
)

router = APIRouter(prefix="/teams", tags=["teams"])


# Request/Response models
class TeamCreate(BaseModel):
    """Create team request"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)


class TeamUpdate(BaseModel):
    """Update team request"""
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=500)


class TeamMemberAdd(BaseModel):
    """Add team member request"""
    user_id: str
    role: str = Field("analyst", description="Role: manager, analyst, viewer")


class TeamMemberUpdate(BaseModel):
    """Update team member request"""
    role: str = Field(..., description="Role: manager, analyst, viewer")


class TeamResponse(BaseModel):
    """Team response"""
    id: str
    name: str
    description: Optional[str]
    member_count: int = 0
    created_at: datetime


class TeamMemberResponse(BaseModel):
    """Team member response"""
    user_id: str
    email: Optional[str]
    full_name: Optional[str]
    role: str
    joined_at: Optional[datetime]


class TeamDetail(BaseModel):
    """Detailed team response"""
    id: str
    name: str
    description: Optional[str]
    members: List[TeamMemberResponse]
    created_at: datetime


class RoleUpdate(BaseModel):
    """Update user role request"""
    role: str = Field(..., description="Role: admin, manager, analyst, viewer")


class RoleResponse(BaseModel):
    """Role info response"""
    role: str
    permissions: List[str]


# Endpoints
@router.post("", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team_endpoint(
    team_data: TeamCreate,
    current_user: dict = Depends(require_permission(Permission.TEAM_CREATE)),
    sb = Depends(get_supabase_client)
):
    """
    Create a new team
    """
    try:
        team = await create_team(
            organization_id=current_user["organization_id"],
            name=team_data.name,
            description=team_data.description,
            created_by=current_user["id"]
        )
        
        return TeamResponse(
            id=team["id"],
            name=team["name"],
            description=team.get("description"),
            member_count=1,  # Creator is automatically added
            created_at=team.get("created_at", datetime.now(timezone.utc))
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create team: {str(e)}"
        )


@router.get("", response_model=List[TeamResponse])
async def list_teams(
    current_user: dict = Depends(require_permission(Permission.TEAM_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    List all teams in the organization
    """
    try:
        org_id = current_user["organization_id"]
        
        # Get teams with member counts
        teams_result = sb.table("teams").select(
            "id, name, description, created_at"
        ).eq("organization_id", org_id).execute()
        
        teams = []
        for team in teams_result.data or []:
            # Get member count
            members = sb.table("team_members").select(
                "id", count="exact"
            ).eq("team_id", team["id"]).execute()
            
            teams.append(TeamResponse(
                id=team["id"],
                name=team["name"],
                description=team.get("description"),
                member_count=members.count or 0,
                created_at=team.get("created_at", datetime.now(timezone.utc))
            ))
        
        return teams
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list teams: {str(e)}"
        )


@router.get("/my", response_model=List[TeamResponse])
async def get_my_teams(
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Get teams the current user belongs to
    """
    try:
        teams = await get_user_teams(current_user["id"])
        
        return [
            TeamResponse(
                id=team["id"],
                name=team["name"],
                description=team.get("description"),
                member_count=0,  # Could query if needed
                created_at=datetime.now(timezone.utc)
            )
            for team in teams
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get teams: {str(e)}"
        )


@router.get("/{team_id}", response_model=TeamDetail)
async def get_team(
    team_id: str,
    current_user: dict = Depends(require_permission(Permission.TEAM_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    Get team details including members
    """
    try:
        # Get team
        team_result = sb.table("teams").select("*").eq("id", team_id).execute()
        
        if not team_result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )
        
        team = team_result.data[0]
        
        # Get members
        members_result = sb.table("team_members").select(
            "user_id, role, created_at, user_profiles(email, full_name)"
        ).eq("team_id", team_id).execute()
        
        members = []
        for member in members_result.data or []:
            profile = member.get("user_profiles", {}) or {}
            members.append(TeamMemberResponse(
                user_id=member["user_id"],
                email=profile.get("email"),
                full_name=profile.get("full_name"),
                role=member.get("role", "viewer"),
                joined_at=member.get("created_at")
            ))
        
        return TeamDetail(
            id=team["id"],
            name=team["name"],
            description=team.get("description"),
            members=members,
            created_at=team.get("created_at", datetime.now(timezone.utc))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get team: {str(e)}"
        )


@router.put("/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: str,
    team_data: TeamUpdate,
    current_user: dict = Depends(require_permission(Permission.TEAM_EDIT)),
    sb = Depends(get_supabase_client)
):
    """
    Update team details
    """
    try:
        updates = {}
        if team_data.name is not None:
            updates["name"] = team_data.name
        if team_data.description is not None:
            updates["description"] = team_data.description
        
        if not updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields to update"
            )
        
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        result = sb.table("teams").update(updates).eq("id", team_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team not found"
            )
        
        team = result.data[0]
        
        return TeamResponse(
            id=team["id"],
            name=team["name"],
            description=team.get("description"),
            member_count=0,
            created_at=team.get("created_at", datetime.now(timezone.utc))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update team: {str(e)}"
        )


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: str,
    current_user: dict = Depends(require_permission(Permission.TEAM_DELETE)),
    sb = Depends(get_supabase_client)
):
    """
    Delete a team
    """
    try:
        # Delete team members first
        sb.table("team_members").delete().eq("team_id", team_id).execute()
        
        # Delete team
        sb.table("teams").delete().eq("id", team_id).execute()
        
        return None
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete team: {str(e)}"
        )


@router.post("/{team_id}/members", response_model=TeamMemberResponse)
async def add_member_to_team(
    team_id: str,
    member_data: TeamMemberAdd,
    current_user: dict = Depends(require_permission(Permission.TEAM_MANAGE_MEMBERS)),
    sb = Depends(get_supabase_client)
):
    """
    Add a member to a team
    """
    try:
        # Validate role
        valid_roles = ["manager", "analyst", "viewer"]
        if member_data.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {valid_roles}"
            )
        
        role = Role(member_data.role)
        
        # Verify user exists in organization
        profile = sb.table("user_profiles").select(
            "id, email, full_name, organization_id"
        ).eq("id", member_data.user_id).execute()
        
        if not profile.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user_profile = profile.data[0]
        
        if user_profile.get("organization_id") != current_user["organization_id"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is not part of this organization"
            )
        
        await add_team_member(
            team_id=team_id,
            user_id=member_data.user_id,
            role=role,
            added_by=current_user["id"]
        )
        
        return TeamMemberResponse(
            user_id=member_data.user_id,
            email=user_profile.get("email"),
            full_name=user_profile.get("full_name"),
            role=member_data.role,
            joined_at=datetime.now(timezone.utc)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add member: {str(e)}"
        )


@router.put("/{team_id}/members/{user_id}", response_model=TeamMemberResponse)
async def update_team_member(
    team_id: str,
    user_id: str,
    member_data: TeamMemberUpdate,
    current_user: dict = Depends(require_permission(Permission.TEAM_MANAGE_MEMBERS)),
    sb = Depends(get_supabase_client)
):
    """
    Update a team member's role
    """
    try:
        # Validate role
        valid_roles = ["manager", "analyst", "viewer"]
        if member_data.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {valid_roles}"
            )
        
        # Update role
        result = sb.table("team_members").update({
            "role": member_data.role
        }).eq("team_id", team_id).eq("user_id", user_id).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Team member not found"
            )
        
        # Get user profile
        profile = sb.table("user_profiles").select(
            "email, full_name"
        ).eq("id", user_id).execute()
        
        user_profile = profile.data[0] if profile.data else {}
        
        return TeamMemberResponse(
            user_id=user_id,
            email=user_profile.get("email"),
            full_name=user_profile.get("full_name"),
            role=member_data.role,
            joined_at=None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update member: {str(e)}"
        )


@router.delete("/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member_from_team(
    team_id: str,
    user_id: str,
    current_user: dict = Depends(require_permission(Permission.TEAM_MANAGE_MEMBERS)),
    sb = Depends(get_supabase_client)
):
    """
    Remove a member from a team
    """
    try:
        await remove_team_member(team_id, user_id)
        return None
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove member: {str(e)}"
        )


# User role management endpoints
@router.get("/users/{user_id}/role", response_model=RoleResponse)
async def get_user_role(
    user_id: str,
    current_user: dict = Depends(require_permission(Permission.USER_VIEW)),
    sb = Depends(get_supabase_client)
):
    """
    Get a user's role and permissions
    """
    try:
        rbac = RBACService()
        role = await rbac.get_user_role(user_id, current_user["organization_id"])
        
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in organization"
            )
        
        from app.core.rbac import ROLE_PERMISSIONS
        permissions = [p.value for p in ROLE_PERMISSIONS.get(role, set())]
        
        return RoleResponse(
            role=role.value,
            permissions=sorted(permissions)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get role: {str(e)}"
        )


@router.put("/users/{user_id}/role", response_model=RoleResponse)
async def update_user_role(
    user_id: str,
    role_data: RoleUpdate,
    current_user: dict = Depends(require_permission(Permission.USER_CHANGE_ROLE)),
    sb = Depends(get_supabase_client)
):
    """
    Update a user's role in the organization
    """
    try:
        # Validate role
        valid_roles = ["admin", "manager", "analyst", "viewer"]
        if role_data.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {valid_roles}"
            )
        
        role = Role(role_data.role)
        
        rbac = RBACService()
        await rbac.assign_role(
            user_id=user_id,
            organization_id=current_user["organization_id"],
            role=role,
            assigned_by=current_user["id"]
        )
        
        from app.core.rbac import ROLE_PERMISSIONS
        permissions = [p.value for p in ROLE_PERMISSIONS.get(role, set())]
        
        return RoleResponse(
            role=role.value,
            permissions=sorted(permissions)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update role: {str(e)}"
        )


@router.get("/my/role", response_model=RoleResponse)
async def get_my_role(
    current_user: dict = Depends(get_current_user),
    sb = Depends(get_supabase_client)
):
    """
    Get current user's role and permissions
    """
    try:
        # Get organization
        profile = sb.table("user_profiles").select(
            "organization_id, role"
        ).eq("id", current_user["id"]).execute()
        
        if not profile.data or not profile.data[0].get("organization_id"):
            return RoleResponse(
                role="viewer",
                permissions=[]
            )
        
        user_profile = profile.data[0]
        role_str = user_profile.get("role", "viewer")
        
        try:
            role = Role(role_str)
        except ValueError:
            role = Role.VIEWER
        
        from app.core.rbac import ROLE_PERMISSIONS
        permissions = [p.value for p in ROLE_PERMISSIONS.get(role, set())]
        
        return RoleResponse(
            role=role.value,
            permissions=sorted(permissions)
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get role: {str(e)}"
        )
