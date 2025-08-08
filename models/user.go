package models

import (
	"time"

	"github.com/uptrace/bun"
)

// User represents a user in the system
type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID          uint      `json:"id" bun:"id,pk,autoincrement"`
	Username    string    `json:"username" bun:"username,unique,notnull" validate:"required,min=3,max=50"`
	Name        string    `json:"name" bun:"name,notnull" validate:"required,min=1,max=100"`
	Email       string    `json:"email" bun:"email,unique,notnull" validate:"required,email"`
	Password    string    `json:"-" bun:"password,notnull" validate:"required,min=6"`
	PhoneNumber string    `json:"phone_number" bun:"phone_number"`
	Status      string    `json:"status" bun:"status,default:'active'" validate:"oneof=active inactive"`
	RoleID      uint      `json:"role_id" bun:"role_id,notnull"`
	Role        *Role     `json:"role" bun:"rel:belongs-to,join:role_id=id"`
	CreatedAt   time.Time `json:"created_at" bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt   time.Time `json:"updated_at" bun:"updated_at,nullzero,notnull,default:current_timestamp"`
}

// UserResponse represents the user data returned in API responses (without password)
type UserResponse struct {
	ID          uint         `json:"id"`
	Username    string       `json:"username"`
	Name        string       `json:"name"`
	Email       string       `json:"email"`
	PhoneNumber string       `json:"phone_number"`
	Status      string       `json:"status"`
	RoleID      uint         `json:"role_id"`
	Role        RoleResponse `json:"role"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// UserWithPermissions represents user data with embedded permissions for login responses
type UserWithPermissions struct {
	ID          uint              `json:"id"`
	Username    string            `json:"username"`
	Name        string            `json:"name"`
	Email       string            `json:"email"`
	PhoneNumber string            `json:"phone_number"`
	Status      string            `json:"status"`
	RoleID      uint              `json:"role_id"`
	Role        string            `json:"role"`
	Permissions map[string]string `json:"permissions"` // Changed to string for granular format
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ToResponse converts User to UserResponse
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:          u.ID,
		Username:    u.Username,
		Name:        u.Name,
		Email:       u.Email,
		PhoneNumber: u.PhoneNumber,
		Status:      u.Status,
		RoleID:      u.RoleID,
		Role:        u.Role.ToResponse(),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// ToResponseWithPermissions converts User to UserWithPermissions for login responses
func (u *User) ToResponseWithPermissions() UserWithPermissions {
	return UserWithPermissions{
		ID:          u.ID,
		Username:    u.Username,
		Name:        u.Name,
		Email:       u.Email,
		PhoneNumber: u.PhoneNumber,
		Status:      u.Status,
		RoleID:      u.RoleID,
		Role:        u.Role.Name,
		Permissions: u.Role.GetGranularPermissions(), // Use new granular format
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// RegisterRequest represents the request body for user registration
type RegisterRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=50"`
	Name        string `json:"name" validate:"required,min=1,max=100"`
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=6"`
	PhoneNumber string `json:"phone_number"`
	RoleID      uint   `json:"role_id"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse represents the response body for user login with permissions
type LoginResponse struct {
	Token string              `json:"token"`
	User  UserWithPermissions `json:"user"`
}

// UpdateUserRequest represents the request body for user updates
type UpdateUserRequest struct {
	Username    string  `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	Name        string  `json:"name,omitempty" validate:"omitempty,min=1,max=100"`
	Email       string  `json:"email,omitempty" validate:"omitempty,email"`
	Password    string  `json:"password,omitempty" validate:"omitempty,min=6"`
	PhoneNumber *string `json:"phone_number,omitempty"`
	Status      string  `json:"status,omitempty" validate:"omitempty,oneof=active inactive"`
	RoleID      *uint   `json:"role_id,omitempty"`
}
