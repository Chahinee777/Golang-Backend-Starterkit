package controllers

import (
	"context"
	"strconv"
	"strings"
	"time"

	"example.com/config"
	"example.com/models"
	"example.com/utils"
	"github.com/gin-gonic/gin"
	"github.com/uptrace/bun"
)

type AuditController struct {
	config *config.Config
}

func NewAuditController(config *config.Config) *AuditController {
	return &AuditController{config: config}
}

// GetAuditLogs godoc
// @Summary Get audit logs with pagination and filtering
// @Description Retrieve audit logs with optional filtering by action, entity, user, etc.
// @Tags audit
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Param action query string false "Filter by action (comma-separated)"
// @Param entity query string false "Filter by entity (comma-separated)"
// @Param userId query string false "Filter by user ID"
// @Param entityId query string false "Filter by entity ID"
// @Param fromDate query string false "Filter from date (RFC3339)"
// @Param toDate query string false "Filter to date (RFC3339)"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/audit-logs [get]
func (ac *AuditController) GetAuditLogs(c *gin.Context) {
	var query models.GetAuditLogsQuery

	// Parse query parameters
	if err := c.ShouldBindQuery(&query); err != nil {
		utils.BadRequest(c, "INVALID_QUERY", "Invalid query parameters", err.Error())
		return
	}

	// Set defaults
	query.SetDefaults()

	ctx := context.Background()

	// Build the query
	dbQuery := ac.config.DB.NewSelect().Model((*models.AuditLog)(nil))

	// Apply filters
	if len(query.Action) > 0 {
		actions := make([]interface{}, len(query.Action))
		for i, action := range query.Action {
			actions[i] = action
		}
		dbQuery = dbQuery.Where("action IN (?)", bun.In(actions))
	}

	if len(query.Entity) > 0 {
		entities := make([]interface{}, len(query.Entity))
		for i, entity := range query.Entity {
			entities[i] = entity
		}
		dbQuery = dbQuery.Where("entity IN (?)", bun.In(entities))
	}

	if query.UserID != "" {
		dbQuery = dbQuery.Where("user_id = ?", query.UserID)
	}

	if query.EntityID != "" {
		dbQuery = dbQuery.Where("entity_id = ?", query.EntityID)
	}

	if query.FromDate != nil {
		dbQuery = dbQuery.Where("timestamp >= ?", *query.FromDate)
	}

	if query.ToDate != nil {
		dbQuery = dbQuery.Where("timestamp <= ?", *query.ToDate)
	}

	// Get total count for pagination
	totalCount, err := dbQuery.Count(ctx)
	if err != nil {
		utils.InternalError(c, "DATABASE_ERROR", "Failed to count audit logs", err.Error())
		return
	}

	// Apply pagination
	offset := (query.Page - 1) * query.Limit
	dbQuery = dbQuery.Order("timestamp DESC").Limit(query.Limit).Offset(offset)

	// Execute query
	var auditLogs []models.AuditLog
	if err := dbQuery.Scan(ctx, &auditLogs); err != nil {
		utils.InternalError(c, "DATABASE_ERROR", "Failed to fetch audit logs", err.Error())
		return
	}

	// Convert to response format
	var auditLogResponses []models.AuditLogResponse
	for _, log := range auditLogs {
		auditLogResponses = append(auditLogResponses, log.ToResponse())
	}

	// Calculate pagination info
	totalPages := (totalCount + query.Limit - 1) / query.Limit

	response := map[string]interface{}{
		"data": auditLogResponses,
		"pagination": map[string]interface{}{
			"page":       query.Page,
			"limit":      query.Limit,
			"total":      totalCount,
			"totalPages": totalPages,
		},
	}

	utils.OK(c, response)
}

// GetAuditLogById godoc
// @Summary Get audit log by ID
// @Description Retrieve a specific audit log by its ID
// @Tags audit
// @Accept json
// @Produce json
// @Param id path int true "Audit log ID"
// @Security BearerAuth
// @Success 200 {object} models.AuditLogResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/audit-logs/{id} [get]
func (ac *AuditController) GetAuditLogById(c *gin.Context) {
	idStr := c.Param("id")
	if idStr == "" {
		utils.BadRequest(c, "MISSING_ID", "Audit log ID is required", "")
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		utils.BadRequest(c, "INVALID_ID", "Invalid audit log ID format", err.Error())
		return
	}

	ctx := context.Background()
	var auditLog models.AuditLog
	err = ac.config.DB.NewSelect().
		Model(&auditLog).
		Where("id = ?", uint(id)).
		Scan(ctx)

	if err != nil {
		utils.NotFound(c, "AUDIT_LOG_NOT_FOUND", "Audit log not found", err.Error())
		return
	}

	utils.OK(c, auditLog.ToResponse())
}

// CreateAuditLog godoc
// @Summary Create audit log
// @Description Create a new audit log entry
// @Tags audit
// @Accept json
// @Produce json
// @Param request body models.CreateAuditLogRequest true "Audit log data"
// @Security BearerAuth
// @Success 201 {object} models.AuditLogResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/audit-logs [post]
func (ac *AuditController) CreateAuditLog(c *gin.Context) {
	var req models.CreateAuditLogRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	ctx := context.Background()

	// Create audit log
	auditLog := models.AuditLog{
		UserID:      req.UserID,
		UserEmail:   req.UserEmail,
		UserName:    req.UserName,
		Action:      req.Action,
		Entity:      req.Entity,
		EntityID:    req.EntityID,
		EntityName:  req.EntityName,
		Description: req.Description,
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
		Timestamp:   time.Now(),
	}

	// Set changes if provided
	if req.Changes != nil {
		if err := auditLog.SetChanges(req.Changes); err != nil {
			utils.BadRequest(c, "INVALID_CHANGES", "Failed to set changes", err.Error())
			return
		}
	}

	// Insert into database
	_, err := ac.config.DB.NewInsert().Model(&auditLog).Exec(ctx)
	if err != nil {
		utils.InternalError(c, "DATABASE_ERROR", "Failed to create audit log", err.Error())
		return
	}

	utils.Created(c, auditLog.ToResponse())
}

// CreateAuditLogWithUser is a helper function to create an audit log with user context
func (ac *AuditController) CreateAuditLogWithUser(
	user *models.User,
	action models.AuditAction,
	entity models.AuditEntity,
	entityID string,
	entityName string,
	description string,
	changes map[string]*models.AuditChanges,
	ipAddress string,
	userAgent string,
) error {
	auditLog := models.AuditLog{
		UserID:      strconv.Itoa(int(user.ID)),
		UserEmail:   user.Email,
		UserName:    user.Name,
		Action:      action,
		Entity:      entity,
		EntityID:    entityID,
		EntityName:  entityName,
		Description: description,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Timestamp:   time.Now(),
	}

	// Set changes if provided
	if changes != nil {
		if err := auditLog.SetChanges(changes); err != nil {
			return err
		}
	}

	ctx := context.Background()
	// Insert into database
	_, err := ac.config.DB.NewInsert().Model(&auditLog).Exec(ctx)
	return err
}

// CreateSystemAuditLog creates an audit log for system actions (without user context)
func (ac *AuditController) CreateSystemAuditLog(
	action models.AuditAction,
	entity models.AuditEntity,
	entityID string,
	entityName string,
	description string,
	changes map[string]*models.AuditChanges,
) error {
	auditLog := models.AuditLog{
		UserEmail:   "system",
		UserName:    "System",
		Action:      action,
		Entity:      entity,
		EntityID:    entityID,
		EntityName:  entityName,
		Description: description,
		Timestamp:   time.Now(),
	}

	// Set changes if provided
	if changes != nil {
		if err := auditLog.SetChanges(changes); err != nil {
			return err
		}
	}

	ctx := context.Background()
	// Insert into database
	_, err := ac.config.DB.NewInsert().Model(&auditLog).Exec(ctx)
	return err
}

// GetUserAuditLogs godoc
// @Summary Get audit logs for a specific user
// @Description Retrieve audit logs filtered by user ID with pagination
// @Tags audit
// @Accept json
// @Produce json
// @Param userId path string true "User ID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Param action query string false "Filter by action (comma-separated)"
// @Param entity query string false "Filter by entity (comma-separated)"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/users/{userId}/audit-logs [get]
func (ac *AuditController) GetUserAuditLogs(c *gin.Context) {
	userID := c.Param("userId")
	if userID == "" {
		utils.BadRequest(c, "MISSING_USER_ID", "User ID is required", "")
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	// Parse action and entity filters
	var actions []models.AuditAction
	if actionQuery := c.Query("action"); actionQuery != "" {
		actionStrs := strings.Split(actionQuery, ",")
		for _, actionStr := range actionStrs {
			actions = append(actions, models.AuditAction(strings.TrimSpace(actionStr)))
		}
	}

	var entities []models.AuditEntity
	if entityQuery := c.Query("entity"); entityQuery != "" {
		entityStrs := strings.Split(entityQuery, ",")
		for _, entityStr := range entityStrs {
			entities = append(entities, models.AuditEntity(strings.TrimSpace(entityStr)))
		}
	}

	ctx := context.Background()

	// Build query
	dbQuery := ac.config.DB.NewSelect().Model((*models.AuditLog)(nil)).Where("user_id = ?", userID)

	// Apply filters
	if len(actions) > 0 {
		actionInterfaces := make([]interface{}, len(actions))
		for i, action := range actions {
			actionInterfaces[i] = action
		}
		dbQuery = dbQuery.Where("action IN (?)", bun.In(actionInterfaces))
	}

	if len(entities) > 0 {
		entityInterfaces := make([]interface{}, len(entities))
		for i, entity := range entities {
			entityInterfaces[i] = entity
		}
		dbQuery = dbQuery.Where("entity IN (?)", bun.In(entityInterfaces))
	}

	// Get total count
	totalCount, err := dbQuery.Count(ctx)
	if err != nil {
		utils.InternalError(c, "DATABASE_ERROR", "Failed to count audit logs", err.Error())
		return
	}

	// Apply pagination
	offset := (page - 1) * limit
	dbQuery = dbQuery.Order("timestamp DESC").Limit(limit).Offset(offset)

	// Execute query
	var auditLogs []models.AuditLog
	if err := dbQuery.Scan(ctx, &auditLogs); err != nil {
		utils.InternalError(c, "DATABASE_ERROR", "Failed to fetch audit logs", err.Error())
		return
	}

	// Convert to response format
	var auditLogResponses []models.AuditLogResponse
	for _, log := range auditLogs {
		auditLogResponses = append(auditLogResponses, log.ToResponse())
	}

	// Calculate pagination info
	totalPages := (totalCount + limit - 1) / limit

	response := map[string]interface{}{
		"data": auditLogResponses,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      totalCount,
			"totalPages": totalPages,
		},
	}

	utils.OK(c, response)
}
