package utils

// Permission levels for CRUD operations
const (
	PermissionNone   = 0 // No access
	PermissionRead   = 1 // Can view/read
	PermissionCreate = 2 // Can create new items
	PermissionUpdate = 3 // Can edit existing items
	PermissionDelete = 4 // Can delete items
	PermissionFull   = 5 // Full administrative access
)

// Permission module names
const (
	ModuleDashboard = "dashboard"
	ModuleUsers     = "users"
	ModuleRoles     = "roles"
	ModuleAudit     = "audit"
	ModuleSettings  = "settings"
)

// PermissionChecker provides methods to check user permissions
type PermissionChecker struct {
	UserPermissions map[string]int
}

// NewPermissionChecker creates a new permission checker with user permissions
func NewPermissionChecker(permissions map[string]int) *PermissionChecker {
	return &PermissionChecker{
		UserPermissions: permissions,
	}
}

// HasPermission checks if user has permission to perform a specific action on a module
func (pc *PermissionChecker) HasPermission(module string, action string) bool {
	modulePermission, exists := pc.UserPermissions[module]
	if !exists {
		return false
	}

	switch action {
	case "read", "view":
		return modulePermission >= PermissionRead
	case "create":
		return modulePermission >= PermissionCreate
	case "update", "edit":
		return modulePermission >= PermissionUpdate
	case "delete":
		return modulePermission >= PermissionDelete
	default:
		return false
	}
}

// CanRead checks if user can view a specific module
func (pc *PermissionChecker) CanRead(module string) bool {
	return pc.HasPermission(module, "read")
}

// CanCreate checks if user can create in a specific module
func (pc *PermissionChecker) CanCreate(module string) bool {
	return pc.HasPermission(module, "create")
}

// CanUpdate checks if user can edit in a specific module
func (pc *PermissionChecker) CanUpdate(module string) bool {
	return pc.HasPermission(module, "update")
}

// CanDelete checks if user can delete in a specific module
func (pc *PermissionChecker) CanDelete(module string) bool {
	return pc.HasPermission(module, "delete")
}

// GetPermissionLevel returns the permission level for a module
func (pc *PermissionChecker) GetPermissionLevel(module string) int {
	if level, exists := pc.UserPermissions[module]; exists {
		return level
	}
	return PermissionNone
}

// GetPermissionLabel returns a human-readable label for a permission level
func GetPermissionLabel(level int) string {
	switch level {
	case PermissionNone:
		return "No Access"
	case PermissionRead:
		return "Read Only"
	case PermissionCreate:
		return "Read & Create"
	case PermissionUpdate:
		return "Read, Create & Update"
	case PermissionDelete:
		return "Read, Create, Update & Delete"
	case PermissionFull:
		return "Full Access"
	default:
		return "Unknown"
	}
}

// DefaultPermissions returns default permission sets for common roles
func GetDefaultPermissions(roleName string) map[string]int {
	switch roleName {
	case "admin":
		return map[string]int{
			ModuleDashboard: PermissionFull,
			ModuleUsers:     PermissionFull,
			ModuleRoles:     PermissionFull,
			ModuleAudit:     PermissionRead,
			ModuleSettings:  PermissionFull,
		}
	case "manager":
		return map[string]int{
			ModuleDashboard: PermissionRead,
			ModuleUsers:     PermissionUpdate,
			ModuleRoles:     PermissionRead,
			ModuleAudit:     PermissionRead,
			ModuleSettings:  PermissionRead,
		}
	case "user":
		return map[string]int{
			ModuleDashboard: PermissionRead,
			ModuleUsers:     PermissionNone,
			ModuleRoles:     PermissionNone,
			ModuleAudit:     PermissionNone,
			ModuleSettings:  PermissionRead,
		}
	case "viewer":
		return map[string]int{
			ModuleDashboard: PermissionRead,
			ModuleUsers:     PermissionNone,
			ModuleRoles:     PermissionNone,
			ModuleAudit:     PermissionNone,
			ModuleSettings:  PermissionNone,
		}
	default:
		// Default no permissions
		return map[string]int{
			ModuleDashboard: PermissionNone,
			ModuleUsers:     PermissionNone,
			ModuleRoles:     PermissionNone,
			ModuleAudit:     PermissionNone,
			ModuleSettings:  PermissionNone,
		}
	}
}
