"""
Role-Based Access Control (RBAC) for SecureScan Pro
Handles team permissions and authorization
"""
from enum import Enum
from typing import List, Optional, Dict, Any, Set
from functools import wraps
from fastapi import HTTPException, status, Depends
import logging

from app.core.supabase_client import get_supabase
from app.core.dependencies import get_current_user

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """System roles"""
    OWNER = "owner"           # Full control of organization
    ADMIN = "admin"           # Manage teams, users, settings
    MANAGER = "manager"       # Manage scans, view all data
    ANALYST = "analyst"       # Run scans, view results
    VIEWER = "viewer"         # Read-only access
    GUEST = "guest"           # Limited read access


class Permission(str, Enum):
    """Granular permissions"""
    # Organization
    ORG_VIEW = "org:view"
    ORG_EDIT = "org:edit"
    ORG_DELETE = "org:delete"
    ORG_MANAGE_BILLING = "org:manage_billing"
    
    # Team
    TEAM_VIEW = "team:view"
    TEAM_CREATE = "team:create"
    TEAM_EDIT = "team:edit"
    TEAM_DELETE = "team:delete"
    TEAM_MANAGE_MEMBERS = "team:manage_members"
    
    # User
    USER_VIEW = "user:view"
    USER_INVITE = "user:invite"
    USER_EDIT = "user:edit"
    USER_REMOVE = "user:remove"
    USER_CHANGE_ROLE = "user:change_role"
    
    # Asset
    ASSET_VIEW = "asset:view"
    ASSET_CREATE = "asset:create"
    ASSET_EDIT = "asset:edit"
    ASSET_DELETE = "asset:delete"
    
    # Scan
    SCAN_VIEW = "scan:view"
    SCAN_CREATE = "scan:create"
    SCAN_CANCEL = "scan:cancel"
    SCAN_DELETE = "scan:delete"
    SCAN_SCHEDULE = "scan:schedule"
    
    # Vulnerability
    VULN_VIEW = "vuln:view"
    VULN_MARK_FP = "vuln:mark_false_positive"
    VULN_EDIT_STATUS = "vuln:edit_status"
    VULN_ASSIGN = "vuln:assign"
    
    # Report
    REPORT_VIEW = "report:view"
    REPORT_CREATE = "report:create"
    REPORT_EXPORT = "report:export"
    REPORT_DELETE = "report:delete"
    
    # Integration
    INTEGRATION_VIEW = "integration:view"
    INTEGRATION_CREATE = "integration:create"
    INTEGRATION_EDIT = "integration:edit"
    INTEGRATION_DELETE = "integration:delete"
    
    # Settings
    SETTINGS_VIEW = "settings:view"
    SETTINGS_EDIT = "settings:edit"
    
    # Audit
    AUDIT_VIEW = "audit:view"


# Role permission mappings
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.OWNER: set(Permission),  # All permissions
    
    Role.ADMIN: {
        Permission.ORG_VIEW,
        Permission.ORG_EDIT,
        Permission.TEAM_VIEW,
        Permission.TEAM_CREATE,
        Permission.TEAM_EDIT,
        Permission.TEAM_DELETE,
        Permission.TEAM_MANAGE_MEMBERS,
        Permission.USER_VIEW,
        Permission.USER_INVITE,
        Permission.USER_EDIT,
        Permission.USER_REMOVE,
        Permission.USER_CHANGE_ROLE,
        Permission.ASSET_VIEW,
        Permission.ASSET_CREATE,
        Permission.ASSET_EDIT,
        Permission.ASSET_DELETE,
        Permission.SCAN_VIEW,
        Permission.SCAN_CREATE,
        Permission.SCAN_CANCEL,
        Permission.SCAN_DELETE,
        Permission.SCAN_SCHEDULE,
        Permission.VULN_VIEW,
        Permission.VULN_MARK_FP,
        Permission.VULN_EDIT_STATUS,
        Permission.VULN_ASSIGN,
        Permission.REPORT_VIEW,
        Permission.REPORT_CREATE,
        Permission.REPORT_EXPORT,
        Permission.REPORT_DELETE,
        Permission.INTEGRATION_VIEW,
        Permission.INTEGRATION_CREATE,
        Permission.INTEGRATION_EDIT,
        Permission.INTEGRATION_DELETE,
        Permission.SETTINGS_VIEW,
        Permission.SETTINGS_EDIT,
        Permission.AUDIT_VIEW,
    },
    
    Role.MANAGER: {
        Permission.ORG_VIEW,
        Permission.TEAM_VIEW,
        Permission.TEAM_MANAGE_MEMBERS,
        Permission.USER_VIEW,
        Permission.USER_INVITE,
        Permission.ASSET_VIEW,
        Permission.ASSET_CREATE,
        Permission.ASSET_EDIT,
        Permission.SCAN_VIEW,
        Permission.SCAN_CREATE,
        Permission.SCAN_CANCEL,
        Permission.SCAN_SCHEDULE,
        Permission.VULN_VIEW,
        Permission.VULN_MARK_FP,
        Permission.VULN_EDIT_STATUS,
        Permission.VULN_ASSIGN,
        Permission.REPORT_VIEW,
        Permission.REPORT_CREATE,
        Permission.REPORT_EXPORT,
        Permission.INTEGRATION_VIEW,
        Permission.SETTINGS_VIEW,
        Permission.AUDIT_VIEW,
    },
    
    Role.ANALYST: {
        Permission.ORG_VIEW,
        Permission.TEAM_VIEW,
        Permission.USER_VIEW,
        Permission.ASSET_VIEW,
        Permission.ASSET_CREATE,
        Permission.SCAN_VIEW,
        Permission.SCAN_CREATE,
        Permission.SCAN_CANCEL,
        Permission.VULN_VIEW,
        Permission.VULN_MARK_FP,
        Permission.VULN_EDIT_STATUS,
        Permission.REPORT_VIEW,
        Permission.REPORT_CREATE,
        Permission.REPORT_EXPORT,
        Permission.SETTINGS_VIEW,
    },
    
    Role.VIEWER: {
        Permission.ORG_VIEW,
        Permission.TEAM_VIEW,
        Permission.USER_VIEW,
        Permission.ASSET_VIEW,
        Permission.SCAN_VIEW,
        Permission.VULN_VIEW,
        Permission.REPORT_VIEW,
        Permission.SETTINGS_VIEW,
    },
    
    Role.GUEST: {
        Permission.ORG_VIEW,
        Permission.SCAN_VIEW,
        Permission.VULN_VIEW,
        Permission.REPORT_VIEW,
    },
}


class RBACService:
    """Service for managing role-based access control"""
    
    def __init__(self):
        self.sb = get_supabase()
    
    async def get_user_role(self, user_id: str, organization_id: str) -> Optional[Role]:
        """
        Get user's role in an organization
        """
        result = self.sb.table("user_profiles").select(
            "role"
        ).eq("id", user_id).eq("organization_id", organization_id).execute()
        
        if not result.data:
            return None
        
        role_str = result.data[0].get("role", "viewer")
        try:
            return Role(role_str)
        except ValueError:
            return Role.VIEWER
    
    async def get_user_team_role(
        self,
        user_id: str,
        team_id: str
    ) -> Optional[Role]:
        """
        Get user's role in a specific team
        """
        result = self.sb.table("team_members").select(
            "role"
        ).eq("user_id", user_id).eq("team_id", team_id).execute()
        
        if not result.data:
            return None
        
        role_str = result.data[0].get("role", "viewer")
        try:
            return Role(role_str)
        except ValueError:
            return Role.VIEWER
    
    async def has_permission(
        self,
        user_id: str,
        organization_id: str,
        permission: Permission,
        team_id: Optional[str] = None
    ) -> bool:
        """
        Check if user has a specific permission
        """
        # Get organization role
        org_role = await self.get_user_role(user_id, organization_id)
        
        if org_role:
            org_permissions = ROLE_PERMISSIONS.get(org_role, set())
            if permission in org_permissions:
                return True
        
        # Check team role if team_id provided
        if team_id:
            team_role = await self.get_user_team_role(user_id, team_id)
            if team_role:
                team_permissions = ROLE_PERMISSIONS.get(team_role, set())
                if permission in team_permissions:
                    return True
        
        return False
    
    async def get_user_permissions(
        self,
        user_id: str,
        organization_id: str,
        team_id: Optional[str] = None
    ) -> Set[Permission]:
        """
        Get all permissions for a user
        """
        permissions = set()
        
        # Get organization permissions
        org_role = await self.get_user_role(user_id, organization_id)
        if org_role:
            permissions.update(ROLE_PERMISSIONS.get(org_role, set()))
        
        # Add team permissions
        if team_id:
            team_role = await self.get_user_team_role(user_id, team_id)
            if team_role:
                permissions.update(ROLE_PERMISSIONS.get(team_role, set()))
        
        return permissions
    
    async def assign_role(
        self,
        user_id: str,
        organization_id: str,
        role: Role,
        assigned_by: str
    ) -> bool:
        """
        Assign a role to a user in an organization
        """
        # Verify assigner has permission
        if not await self.has_permission(
            assigned_by,
            organization_id,
            Permission.USER_CHANGE_ROLE
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to change user roles"
            )
        
        # Cannot assign owner role (must be transferred)
        if role == Role.OWNER:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Owner role cannot be assigned. Use ownership transfer."
            )
        
        # Update user role
        self.sb.table("user_profiles").update({
            "role": role.value
        }).eq("id", user_id).eq("organization_id", organization_id).execute()
        
        # Log audit event
        await self._log_audit(
            organization_id=organization_id,
            action="role_assigned",
            actor_id=assigned_by,
            target_id=user_id,
            details={"new_role": role.value}
        )
        
        return True
    
    async def assign_team_role(
        self,
        user_id: str,
        team_id: str,
        organization_id: str,
        role: Role,
        assigned_by: str
    ) -> bool:
        """
        Assign a role to a user in a team
        """
        # Verify assigner has permission
        if not await self.has_permission(
            assigned_by,
            organization_id,
            Permission.TEAM_MANAGE_MEMBERS,
            team_id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to manage team members"
            )
        
        # Update or insert team member
        existing = self.sb.table("team_members").select("id").eq(
            "user_id", user_id
        ).eq("team_id", team_id).execute()
        
        if existing.data:
            self.sb.table("team_members").update({
                "role": role.value
            }).eq("user_id", user_id).eq("team_id", team_id).execute()
        else:
            self.sb.table("team_members").insert({
                "user_id": user_id,
                "team_id": team_id,
                "role": role.value
            }).execute()
        
        # Log audit event
        await self._log_audit(
            organization_id=organization_id,
            action="team_role_assigned",
            actor_id=assigned_by,
            target_id=user_id,
            details={"team_id": team_id, "new_role": role.value}
        )
        
        return True
    
    async def transfer_ownership(
        self,
        organization_id: str,
        current_owner_id: str,
        new_owner_id: str
    ) -> bool:
        """
        Transfer organization ownership
        """
        # Verify current user is owner
        current_role = await self.get_user_role(current_owner_id, organization_id)
        if current_role != Role.OWNER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the owner can transfer ownership"
            )
        
        # Verify new owner is part of organization
        new_user = self.sb.table("user_profiles").select("id").eq(
            "id", new_owner_id
        ).eq("organization_id", organization_id).execute()
        
        if not new_user.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New owner must be a member of the organization"
            )
        
        # Update roles
        self.sb.table("user_profiles").update({
            "role": Role.ADMIN.value
        }).eq("id", current_owner_id).eq("organization_id", organization_id).execute()
        
        self.sb.table("user_profiles").update({
            "role": Role.OWNER.value
        }).eq("id", new_owner_id).eq("organization_id", organization_id).execute()
        
        # Log audit event
        await self._log_audit(
            organization_id=organization_id,
            action="ownership_transferred",
            actor_id=current_owner_id,
            target_id=new_owner_id,
            details={}
        )
        
        return True
    
    async def _log_audit(
        self,
        organization_id: str,
        action: str,
        actor_id: str,
        target_id: Optional[str] = None,
        details: Dict = None
    ):
        """
        Log an audit event
        """
        try:
            from datetime import datetime, timezone
            
            self.sb.table("audit_logs").insert({
                "organization_id": organization_id,
                "action": action,
                "actor_id": actor_id,
                "target_type": "user",
                "target_id": target_id,
                "details": details or {},
                "created_at": datetime.now(timezone.utc).isoformat()
            }).execute()
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")


# FastAPI dependency for permission checks
def require_permission(permission: Permission):
    """
    Dependency factory for permission requirements
    
    Usage:
        @router.get("/scans")
        async def list_scans(
            user: dict = Depends(require_permission(Permission.SCAN_VIEW))
        ):
            ...
    """
    async def permission_dependency(
        current_user: dict = Depends(get_current_user)
    ):
        user_id = current_user.get("id")
        org_id = current_user.get("organization_id")
        
        if not org_id:
            # Try to get org from profile
            sb = get_supabase()
            profile = sb.table("user_profiles").select(
                "organization_id"
            ).eq("id", user_id).execute()
            
            if profile.data:
                org_id = profile.data[0].get("organization_id")
        
        if not org_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with an organization"
            )
        
        rbac = RBACService()
        has_perm = await rbac.has_permission(user_id, org_id, permission)
        
        if not has_perm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}"
            )
        
        # Add org_id to user context
        current_user["organization_id"] = org_id
        return current_user
    
    return permission_dependency


def require_role(min_role: Role):
    """
    Dependency factory for role requirements
    
    Usage:
        @router.delete("/org")
        async def delete_org(
            user: dict = Depends(require_role(Role.OWNER))
        ):
            ...
    """
    role_hierarchy = [Role.GUEST, Role.VIEWER, Role.ANALYST, Role.MANAGER, Role.ADMIN, Role.OWNER]
    
    async def role_dependency(
        current_user: dict = Depends(get_current_user)
    ):
        user_id = current_user.get("id")
        org_id = current_user.get("organization_id")
        
        if not org_id:
            sb = get_supabase()
            profile = sb.table("user_profiles").select(
                "organization_id"
            ).eq("id", user_id).execute()
            
            if profile.data:
                org_id = profile.data[0].get("organization_id")
        
        if not org_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not associated with an organization"
            )
        
        rbac = RBACService()
        user_role = await rbac.get_user_role(user_id, org_id)
        
        if not user_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No role assigned"
            )
        
        user_level = role_hierarchy.index(user_role) if user_role in role_hierarchy else -1
        required_level = role_hierarchy.index(min_role)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {min_role.value} role or higher"
            )
        
        current_user["organization_id"] = org_id
        current_user["role"] = user_role.value
        return current_user
    
    return role_dependency


# Team management functions
async def create_team(
    organization_id: str,
    name: str,
    description: Optional[str] = None,
    created_by: str = None
) -> Dict[str, Any]:
    """
    Create a new team
    """
    import uuid
    from datetime import datetime, timezone
    
    sb = get_supabase()
    
    team = {
        "id": str(uuid.uuid4()),
        "organization_id": organization_id,
        "name": name,
        "description": description,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    result = sb.table("teams").insert(team).execute()
    
    # Add creator as team lead
    if created_by:
        sb.table("team_members").insert({
            "team_id": team["id"],
            "user_id": created_by,
            "role": Role.MANAGER.value
        }).execute()
    
    return result.data[0] if result.data else team


async def add_team_member(
    team_id: str,
    user_id: str,
    role: Role = Role.ANALYST,
    added_by: str = None
) -> bool:
    """
    Add a member to a team
    """
    sb = get_supabase()
    
    # Check if already a member
    existing = sb.table("team_members").select("id").eq(
        "team_id", team_id
    ).eq("user_id", user_id).execute()
    
    if existing.data:
        # Update role
        sb.table("team_members").update({
            "role": role.value
        }).eq("team_id", team_id).eq("user_id", user_id).execute()
    else:
        # Add new member
        sb.table("team_members").insert({
            "team_id": team_id,
            "user_id": user_id,
            "role": role.value
        }).execute()
    
    return True


async def remove_team_member(team_id: str, user_id: str) -> bool:
    """
    Remove a member from a team
    """
    sb = get_supabase()
    sb.table("team_members").delete().eq(
        "team_id", team_id
    ).eq("user_id", user_id).execute()
    
    return True


async def get_user_teams(user_id: str) -> List[Dict[str, Any]]:
    """
    Get all teams a user is part of
    """
    sb = get_supabase()
    
    result = sb.table("team_members").select(
        "team_id, role, teams(id, name, description)"
    ).eq("user_id", user_id).execute()
    
    teams = []
    for membership in result.data or []:
        team_info = membership.get("teams", {})
        teams.append({
            "id": membership.get("team_id"),
            "name": team_info.get("name"),
            "description": team_info.get("description"),
            "role": membership.get("role")
        })
    
    return teams
