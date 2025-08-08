package models

import (
	"encoding/json"
	"log"
	"time"

	"github.com/uptrace/bun"
)

// Role represents a role in the RBAC system
type Role struct {
	bun.BaseModel `bun:"table:roles,alias:r"`

	ID          uint            `json:"id" bun:"id,pk,autoincrement"`
	Name        string          `json:"name" bun:"name,unique,notnull" validate:"required,min=1,max=50"`
	Description string          `json:"description" bun:"description,type:text"`
	Permissions json.RawMessage `json:"permissions" bun:"permissions,type:jsonb,notnull"`
	IsActive    bool            `json:"is_active" bun:"is_active,default:true"`
	CreatedAt   time.Time       `json:"created_at" bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt   time.Time       `json:"updated_at" bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

// RoleResponse represents the role data returned in API responses
type RoleResponse struct {
	ID          uint              `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Permissions map[string]string `json:"permissions"` // Changed to string for comma-separated format
	IsActive    bool              `json:"is_active"`
	UserCount   int               `json:"user_count"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// GranularPermissions represents the structured permission format for API requests
type GranularPermissions struct {
	Users     string `json:"users"`     // "1,1,1,1" format: view,create,edit,delete
	Roles     string `json:"roles"`     // "1,1,1,1" format: view,create,edit,delete
	Audit     string `json:"audit"`     // "1,0,0,0" format: view,create,edit,delete
	Settings  string `json:"settings"`  // "1,0,1,0" format: view,create,edit,delete
	Dashboard string `json:"dashboard"` // "1,0,0,0" format: view,create,edit,delete
}

// ToResponse converts Role to RoleResponse with granular permissions
func (r *Role) ToResponse() RoleResponse {
	granularPermissions := make(map[string]string)
	if r.Permissions != nil {
		log.Printf("Raw permissions data: %s", string(r.Permissions))
		var oldPermissions map[string]int
		if err := json.Unmarshal(r.Permissions, &oldPermissions); err == nil {
			// Convert old format to new granular format
			log.Printf("Converting old permissions: %+v", oldPermissions)
			granularPermissions = r.convertToGranularFormat(oldPermissions)
		} else {
			// Try to unmarshal as new granular format
			log.Printf("Trying granular format, error was: %v", err)
			json.Unmarshal(r.Permissions, &granularPermissions)
		}
		log.Printf("Final granular permissions: %+v", granularPermissions)
	}

	return RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: granularPermissions,
		IsActive:    r.IsActive,
		UserCount:   0, // Default, should be populated by controller
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// convertToGranularFormat converts old integer permissions to new granular format
func (r *Role) convertToGranularFormat(oldPermissions map[string]int) map[string]string {
	granular := make(map[string]string)

	for module, level := range oldPermissions {
		switch level {
		case 0: // No access
			granular[module] = "0,0,0,0"
		case 1: // Read only
			granular[module] = "1,0,0,0"
		case 2: // Read + Create
			granular[module] = "1,1,0,0"
		case 3: // Read + Create + Update
			granular[module] = "1,1,1,0"
		case 4: // Read + Create + Update + Delete
			granular[module] = "1,1,1,1"
		case 5: // Full access (same as 4)
			granular[module] = "1,1,1,1"
		default:
			granular[module] = "0,0,0,0"
		}
	}

	// Set default permissions for modules that might not exist
	if _, exists := granular["users"]; !exists {
		granular["users"] = "0,0,0,0"
	}
	if _, exists := granular["roles"]; !exists {
		granular["roles"] = "0,0,0,0"
	}
	if _, exists := granular["audit"]; !exists {
		granular["audit"] = "0,0,0,0"
	}
	if _, exists := granular["settings"]; !exists {
		granular["settings"] = "0,0,0,0"
	}
	if _, exists := granular["dashboard"]; !exists {
		granular["dashboard"] = "0,0,0,0"
	}

	return granular
}

// ToResponseWithUserCount converts Role to RoleResponse with user count
func (r *Role) ToResponseWithUserCount(userCount int) RoleResponse {
	granularPermissions := make(map[string]string)
	if r.Permissions != nil {
		var oldPermissions map[string]int
		if err := json.Unmarshal(r.Permissions, &oldPermissions); err == nil {
			// Convert old format to new granular format
			granularPermissions = r.convertToGranularFormat(oldPermissions)
		} else {
			// Try to unmarshal as new granular format
			json.Unmarshal(r.Permissions, &granularPermissions)
		}
	}

	return RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: granularPermissions,
		IsActive:    r.IsActive,
		UserCount:   userCount,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// GetPermissions returns the permissions as a map (legacy - returns old integer format)
func (r *Role) GetPermissions() map[string]int {
	permissions := make(map[string]int)
	if r.Permissions != nil {
		json.Unmarshal(r.Permissions, &permissions)
	}
	return permissions
}

// GetGranularPermissions returns the permissions in the new granular string format
func (r *Role) GetGranularPermissions() map[string]string {
	granularPermissions := make(map[string]string)
	if r.Permissions != nil {
		// First try to parse as new granular format
		if err := json.Unmarshal(r.Permissions, &granularPermissions); err == nil {
			// Check if it's already in granular format (contains comma-separated values)
			for _, v := range granularPermissions {
				if len(v) > 1 && (v[0] == '0' || v[0] == '1') {
					return granularPermissions
				}
			}
		}

		// If not in granular format, try to parse as old integer format and convert
		var oldPermissions map[string]int
		if err := json.Unmarshal(r.Permissions, &oldPermissions); err == nil {
			// Convert old format to new granular format
			for module, level := range oldPermissions {
				switch level {
				case 0:
					granularPermissions[module] = "0,0,0,0" // No access
				case 1:
					granularPermissions[module] = "1,0,0,0" // View only
				case 2:
					granularPermissions[module] = "1,1,0,0" // View + Create
				case 3:
					granularPermissions[module] = "1,1,1,0" // View + Create + Edit
				case 4:
					granularPermissions[module] = "1,1,1,1" // Full access (with delete)
				case 5:
					granularPermissions[module] = "1,1,1,1" // Full access
				default:
					granularPermissions[module] = "0,0,0,0" // Default to no access
				}
			}
		}
	}
	return granularPermissions
}

// SetPermissions sets the permissions from a map (supports both old and new formats)
func (r *Role) SetPermissions(permissions interface{}) error {
	data, err := json.Marshal(permissions)
	if err != nil {
		return err
	}
	r.Permissions = data
	return nil
}

// CreateRoleRequest represents the request body for role creation
type CreateRoleRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=50"`
	Description string            `json:"description"`
	Permissions map[string]string `json:"permissions" validate:"required"` // Changed to granular format
	IsActive    *bool             `json:"is_active"`
}

// UpdateRoleRequest represents the request body for role updates
type UpdateRoleRequest struct {
	Name        string            `json:"name,omitempty" validate:"omitempty,min=1,max=50"`
	Description string            `json:"description,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"` // Changed to granular format
	IsActive    *bool             `json:"is_active,omitempty"`
}
