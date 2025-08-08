package models

import (
	"encoding/json"
	"time"

	"github.com/uptrace/bun"
)

// AuditAction represents the type of action performed
type AuditAction string

const (
	AuditActionCreate AuditAction = "create"
	AuditActionUpdate AuditAction = "update"
	AuditActionDelete AuditAction = "delete"
	AuditActionView   AuditAction = "view"
	AuditActionLogin  AuditAction = "login"
	AuditActionLogout AuditAction = "logout"
)

// AuditEntity represents the type of entity being audited
type AuditEntity string

const (
	AuditEntityUser       AuditEntity = "user"
	AuditEntityRole       AuditEntity = "role"
	AuditEntityPermission AuditEntity = "permission"
	AuditEntitySettings   AuditEntity = "settings"
	AuditEntitySession    AuditEntity = "session"
)

// AuditChanges represents the before and after state of an entity
type AuditChanges struct {
	Before interface{} `json:"before,omitempty"`
	After  interface{} `json:"after,omitempty"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	bun.BaseModel `bun:"table:audit_logs,alias:al"`

	ID          uint            `bun:"id,pk,autoincrement" json:"id"`
	UserID      string          `bun:"user_id,nullzero" json:"userId"`
	UserEmail   string          `bun:"user_email" json:"userEmail"`
	UserName    string          `bun:"user_name" json:"userName"`
	Action      AuditAction     `bun:"action,notnull" json:"action"`
	Entity      AuditEntity     `bun:"entity,notnull" json:"entity"`
	EntityID    string          `bun:"entity_id" json:"entityId"`
	EntityName  string          `bun:"entity_name" json:"entityName"`
	Description string          `bun:"description" json:"description"`
	IPAddress   string          `bun:"ip_address" json:"ipAddress"`
	UserAgent   string          `bun:"user_agent" json:"userAgent"`
	Changes     json.RawMessage `bun:"changes,type:jsonb" json:"changes,omitempty"`
	Timestamp   time.Time       `bun:",nullzero,notnull,default:current_timestamp" json:"timestamp"`
}

// AuditLogResponse represents the response structure for audit logs
type AuditLogResponse struct {
	ID          uint                     `json:"id"`
	UserID      string                   `json:"userId"`
	UserEmail   string                   `json:"userEmail"`
	UserName    string                   `json:"userName"`
	Action      AuditAction              `json:"action"`
	Entity      AuditEntity              `json:"entity"`
	EntityID    string                   `json:"entityId"`
	EntityName  string                   `json:"entityName"`
	Description string                   `json:"description"`
	IPAddress   string                   `json:"ipAddress"`
	UserAgent   string                   `json:"userAgent"`
	Changes     map[string]*AuditChanges `json:"changes,omitempty"`
	Timestamp   time.Time                `json:"timestamp"`
}

// ToResponse converts AuditLog to AuditLogResponse
func (al *AuditLog) ToResponse() AuditLogResponse {
	response := AuditLogResponse{
		ID:          al.ID,
		UserID:      al.UserID,
		UserEmail:   al.UserEmail,
		UserName:    al.UserName,
		Action:      al.Action,
		Entity:      al.Entity,
		EntityID:    al.EntityID,
		EntityName:  al.EntityName,
		Description: al.Description,
		IPAddress:   al.IPAddress,
		UserAgent:   al.UserAgent,
		Timestamp:   al.Timestamp,
	}

	// Parse changes if they exist
	if al.Changes != nil {
		var changes map[string]*AuditChanges
		if err := json.Unmarshal(al.Changes, &changes); err == nil {
			response.Changes = changes
		}
	}

	return response
}

// SetChanges sets the changes field from a map
func (al *AuditLog) SetChanges(changes map[string]*AuditChanges) error {
	if changes == nil {
		al.Changes = nil
		return nil
	}

	data, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	al.Changes = data
	return nil
}

// CreateAuditLogRequest represents the request body for creating audit logs
type CreateAuditLogRequest struct {
	UserID      string                   `json:"userId"`
	UserEmail   string                   `json:"userEmail"`
	UserName    string                   `json:"userName"`
	Action      AuditAction              `json:"action" validate:"required"`
	Entity      AuditEntity              `json:"entity" validate:"required"`
	EntityID    string                   `json:"entityId"`
	EntityName  string                   `json:"entityName"`
	Description string                   `json:"description" validate:"required"`
	IPAddress   string                   `json:"ipAddress"`
	UserAgent   string                   `json:"userAgent"`
	Changes     map[string]*AuditChanges `json:"changes,omitempty"`
}

// GetAuditLogsQuery represents query parameters for listing audit logs
type GetAuditLogsQuery struct {
	Page     int           `query:"page" validate:"min=1"`
	Limit    int           `query:"limit" validate:"min=1,max=100"`
	Action   []AuditAction `query:"action"`
	Entity   []AuditEntity `query:"entity"`
	UserID   string        `query:"userId"`
	EntityID string        `query:"entityId"`
	FromDate *time.Time    `query:"fromDate"`
	ToDate   *time.Time    `query:"toDate"`
}

// Default values for pagination
func (q *GetAuditLogsQuery) SetDefaults() {
	if q.Page == 0 {
		q.Page = 1
	}
	if q.Limit == 0 {
		q.Limit = 20
	}
}
