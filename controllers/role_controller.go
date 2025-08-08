package controllers

import (
	"context"
	"net/http"
	"strconv"

	"example.com/config"
	"example.com/models"
	"github.com/gin-gonic/gin"
)

type RoleController struct {
	config          *config.Config
	auditController *AuditController
}

func NewRoleController(config *config.Config) *RoleController {
	return &RoleController{
		config:          config,
		auditController: NewAuditController(config),
	}
}

// GetAllRoles godoc
// @Summary Get all roles (Admin only)
// @Description Get all roles with their permissions
// @Tags roles
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.RoleResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/roles [get]
func (rc *RoleController) GetAllRoles(c *gin.Context) {
	ctx := context.Background()
	var roles []models.Role

	if err := rc.config.DB.NewSelect().Model(&roles).Scan(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to fetch roles",
		})
		return
	}

	// Convert to response format with user counts
	var rolesResponse []models.RoleResponse
	for _, role := range roles {
		// Count users with this role
		userCount, err := rc.config.DB.NewSelect().
			Model((*models.User)(nil)).
			Where("role_id = ?", role.ID).
			Count(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to count users for role",
			})
			return
		}

		rolesResponse = append(rolesResponse, role.ToResponseWithUserCount(userCount))
	}

	c.JSON(http.StatusOK, rolesResponse)
}

// GetRole godoc
// @Summary Get role by ID (Admin only)
// @Description Get a specific role by its ID
// @Tags roles
// @Produce json
// @Param id path int true "Role ID"
// @Security BearerAuth
// @Success 200 {object} models.RoleResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/roles/{id} [get]
func (rc *RoleController) GetRole(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid role ID format",
		})
		return
	}

	var role models.Role
	ctx := context.Background()

	if err := rc.config.DB.NewSelect().Model(&role).Where("id = ?", roleID).Scan(ctx); err != nil {
		if err.Error() == "sql: no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Role not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to fetch role",
			})
		}
		return
	}

	c.JSON(http.StatusOK, role.ToResponse())
}

// CreateRole godoc
// @Summary Create new role (Admin only)
// @Description Create a new role with permissions
// @Tags roles
// @Accept json
// @Produce json
// @Param role body models.CreateRoleRequest true "Role creation data"
// @Security BearerAuth
// @Success 201 {object} models.RoleResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/roles [post]
func (rc *RoleController) CreateRole(c *gin.Context) {
	var req models.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request format",
		})
		return
	}

	// Validate request
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Role name is required",
		})
		return
	}

	ctx := context.Background()

	// Check if role name already exists
	var existingRole models.Role
	if err := rc.config.DB.NewSelect().Model(&existingRole).Where("name = ?", req.Name).Scan(ctx); err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":   "conflict",
			"message": "Role name already exists",
		})
		return
	}

	// Create new role
	role := models.Role{
		Name:        req.Name,
		Description: req.Description,
		IsActive:    true,
	}

	// Set permissions
	if err := role.SetPermissions(req.Permissions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid permissions format",
		})
		return
	}

	if _, err := rc.config.DB.NewInsert().Model(&role).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to create role",
		})
		return
	}

	// Create audit log for role creation
	currentUserID, _ := c.Get("user_id")
	var currentUser models.User
	if err := rc.config.DB.NewSelect().Model(&currentUser).Where("id = ?", currentUserID).Scan(ctx); err == nil {
		ipAddress := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		changes := map[string]*models.AuditChanges{
			"name":        {After: role.Name},
			"description": {After: role.Description},
			"permissions": {After: req.Permissions},
			"is_active":   {After: role.IsActive},
		}

		err = rc.auditController.CreateAuditLogWithUser(
			&currentUser,
			models.AuditActionCreate,
			models.AuditEntityRole,
			strconv.Itoa(int(role.ID)),
			role.Name,
			"New role created",
			changes,
			ipAddress,
			userAgent,
		)
		if err != nil {
			// Log error but don't fail the creation process
			// You might want to use a logger here
			// log.Printf("Failed to create audit log for role creation: %v", err)
		}
	}

	c.JSON(http.StatusCreated, role.ToResponse())
}

// UpdateRole godoc
// @Summary Update role (Admin only)
// @Description Update an existing role and its permissions
// @Tags roles
// @Accept json
// @Produce json
// @Param id path int true "Role ID"
// @Param role body models.UpdateRoleRequest true "Role update data"
// @Security BearerAuth
// @Success 200 {object} models.RoleResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/roles/{id} [put]
func (rc *RoleController) UpdateRole(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid role ID format",
		})
		return
	}

	var req models.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request format",
		})
		return
	}

	ctx := context.Background()

	// Get existing role
	var role models.Role
	if err := rc.config.DB.NewSelect().Model(&role).Where("id = ?", roleID).Scan(ctx); err != nil {
		if err.Error() == "sql: no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Role not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to fetch role",
			})
		}
		return
	}

	// Validate request
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Role name is required",
		})
		return
	}

	// Check if new name conflicts with existing role (excluding current role)
	if req.Name != role.Name {
		var existingRole models.Role
		if err := rc.config.DB.NewSelect().Model(&existingRole).Where("name = ? AND id != ?", req.Name, roleID).Scan(ctx); err == nil {
			c.JSON(http.StatusConflict, gin.H{
				"error":   "conflict",
				"message": "Role name already exists",
			})
			return
		}
	}

	// Update role fields
	role.Name = req.Name
	role.Description = req.Description
	if req.IsActive != nil {
		role.IsActive = *req.IsActive
	}

	// Update permissions
	if err := role.SetPermissions(req.Permissions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid permissions format",
		})
		return
	}

	// Save updated role
	if _, err := rc.config.DB.NewUpdate().Model(&role).Where("id = ?", roleID).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to update role",
		})
		return
	}

	c.JSON(http.StatusOK, role.ToResponse())
}

// DeleteRole godoc
// @Summary Delete role (Admin only)
// @Description Delete a role (only if no users are assigned to it)
// @Tags roles
// @Produce json
// @Param id path int true "Role ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/roles/{id} [delete]
func (rc *RoleController) DeleteRole(c *gin.Context) {
	roleID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid role ID format",
		})
		return
	}

	ctx := context.Background()

	// Get existing role
	var role models.Role
	if err := rc.config.DB.NewSelect().Model(&role).Where("id = ?", roleID).Scan(ctx); err != nil {
		if err.Error() == "sql: no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Role not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to fetch role",
			})
		}
		return
	}

	// Prevent deletion of admin role
	if role.Name == "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "Cannot delete admin role",
		})
		return
	}

	// Check if any users are assigned to this role
	userCount, err := rc.config.DB.NewSelect().Model((*models.User)(nil)).Where("role_id = ?", roleID).Count(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to check role usage",
		})
		return
	}

	if userCount > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error":   "conflict",
			"message": "Cannot delete role with assigned users",
		})
		return
	}

	// Delete the role
	if _, err := rc.config.DB.NewDelete().Model(&role).Where("id = ?", roleID).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to delete role",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Role deleted successfully",
	})
}
