package models

import (
	"time"

	"github.com/uptrace/bun"
)

// Module represents a module/feature in the system
type Module struct {
	bun.BaseModel `bun:"table:modules,alias:m"`

	ID          uint      `json:"id" bun:"id,pk,autoincrement"`
	Name        string    `json:"name" bun:"name,unique,notnull" validate:"required,min=1,max=50"`
	DisplayName string    `json:"display_name" bun:"display_name,notnull" validate:"required,min=1,max=100"`
	Description string    `json:"description" bun:"description,type:text"`
	IsActive    bool      `json:"is_active" bun:"is_active,default:true"`
	CreatedAt   time.Time `json:"created_at" bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt   time.Time `json:"updated_at" bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

// ModuleResponse represents the module data returned in API responses
type ModuleResponse struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ToResponse converts Module to ModuleResponse
func (m *Module) ToResponse() ModuleResponse {
	return ModuleResponse{
		ID:          m.ID,
		Name:        m.Name,
		DisplayName: m.DisplayName,
		Description: m.Description,
		IsActive:    m.IsActive,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

// CreateModuleRequest represents the request body for module creation
type CreateModuleRequest struct {
	Name        string `json:"name" validate:"required,min=1,max=50"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Description string `json:"description"`
	IsActive    *bool  `json:"is_active"`
}

// UpdateModuleRequest represents the request body for module updates
type UpdateModuleRequest struct {
	Name        string `json:"name,omitempty" validate:"omitempty,min=1,max=50"`
	DisplayName string `json:"display_name,omitempty" validate:"omitempty,min=1,max=100"`
	Description string `json:"description,omitempty"`
	IsActive    *bool  `json:"is_active,omitempty"`
}

// DefaultModules returns the list of default modules in the system
func DefaultModules() []Module {
	return []Module{
		{
			Name:        "dashboard",
			DisplayName: "Dashboard",
			Description: "Access to the main dashboard and analytics",
			IsActive:    true,
		},
		{
			Name:        "users",
			DisplayName: "User Management",
			Description: "Manage users, create, edit, and delete user accounts",
			IsActive:    true,
		},
		{
			Name:        "roles",
			DisplayName: "Role Management",
			Description: "Manage roles and permissions",
			IsActive:    true,
		},
		{
			Name:        "audit",
			DisplayName: "Audit Logs",
			Description: "View system audit logs and user activity",
			IsActive:    true,
		},
		{
			Name:        "settings",
			DisplayName: "System Settings",
			Description: "Configure system settings and preferences",
			IsActive:    true,
		},
	}
}
