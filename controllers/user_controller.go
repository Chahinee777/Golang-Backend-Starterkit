package controllers

import (
	"context"
	"net/http"
	"strconv"

	"example.com/config"
	"example.com/models"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type UserController struct {
	config          *config.Config
	auditController *AuditController
}

func NewUserController(config *config.Config) *UserController {
	return &UserController{
		config:          config,
		auditController: NewAuditController(config),
	}
}

// CreateUser godoc
// @Summary Create new user (Admin only)
// @Description Create a new user with specified role
// @Tags users
// @Accept json
// @Produce json
// @Param user body models.RegisterRequest true "User creation data"
// @Security BearerAuth
// @Success 201 {object} models.UserResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/users [post]
func (uc *UserController) CreateUser(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	ctx := context.Background()

	// Check if user already exists
	var existingUser models.User
	if err := uc.config.DB.NewSelect().Model(&existingUser).Where("email = ? OR username = ?", req.Email, req.Username).Scan(ctx); err == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":   "conflict",
			"message": "User with this email or username already exists",
		})
		return
	} else if err.Error() != "sql: no rows in result set" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Database error",
		})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to hash password",
		})
		return
	}

	// Determine role to assign
	var roleID uint
	if req.RoleID != 0 {
		// Validate that the provided role exists
		var role models.Role
		if err := uc.config.DB.NewSelect().Model(&role).Where("id = ?", req.RoleID).Scan(ctx); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "Invalid role ID provided",
			})
			return
		}
		roleID = req.RoleID
	} else {
		// Get default user role if no role specified
		var defaultRole models.Role
		if err := uc.config.DB.NewSelect().Model(&defaultRole).Where("name = ?", "user").Scan(ctx); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Default role not found",
			})
			return
		}
		roleID = defaultRole.ID
	}

	// Create user
	user := models.User{
		Username:    req.Username,
		Name:        req.Name,
		Email:       req.Email,
		Password:    string(hashedPassword),
		PhoneNumber: req.PhoneNumber,
		Status:      "active",
		RoleID:      roleID,
	}

	if _, err := uc.config.DB.NewInsert().Model(&user).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to create user",
		})
		return
	}

	// Create audit log for user creation
	currentUserID, _ := c.Get("user_id")
	var currentUser models.User
	if err := uc.config.DB.NewSelect().Model(&currentUser).Where("id = ?", currentUserID).Scan(ctx); err == nil {
		ipAddress := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		changes := map[string]*models.AuditChanges{
			"username": {After: user.Username},
			"name":     {After: user.Name},
			"email":    {After: user.Email},
			"status":   {After: user.Status},
			"role_id":  {After: user.RoleID},
		}

		err = uc.auditController.CreateAuditLogWithUser(
			&currentUser,
			models.AuditActionCreate,
			models.AuditEntityUser,
			strconv.Itoa(int(user.ID)),
			user.Email,
			"New user account created",
			changes,
			ipAddress,
			userAgent,
		)
		if err != nil {
			// Log error but don't fail the creation process
			// You might want to use a logger here
			// log.Printf("Failed to create audit log for user creation: %v", err)
		}
	}

	// Load the role for response
	if err := uc.config.DB.NewSelect().Model(&user).Relation("Role").Where("u.id = ?", user.ID).Scan(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to load user data",
		})
		return
	}

	c.JSON(http.StatusCreated, user.ToResponse())
}

// GetAllUsers godoc
// @Summary Get all users (Admin only)
// @Description Get all users with their roles and permissions
// @Tags users
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.UserResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/users [get]
func (uc *UserController) GetAllUsers(c *gin.Context) {
	ctx := context.Background()
	var users []models.User

	if err := uc.config.DB.NewSelect().Model(&users).Relation("Role").Scan(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to fetch users",
			"details": err.Error(),
		})
		return
	}

	// Convert to response format
	var usersResponse []models.UserResponse
	for _, user := range users {
		usersResponse = append(usersResponse, user.ToResponse())
	}

	c.JSON(http.StatusOK, usersResponse)
}

// GetUser godoc
// @Summary Get user by ID (Admin only)
// @Description Get a specific user by their ID
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Security BearerAuth
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/users/{id} [get]
func (uc *UserController) GetUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid user ID format",
		})
		return
	}

	ctx := context.Background()
	var user models.User

	if err := uc.config.DB.NewSelect().Model(&user).Relation("Role").Where("u.id = ?", userID).Scan(ctx); err != nil {
		if err.Error() == "sql: no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "User not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to fetch user",
			})
		}
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// UpdateUser godoc
// @Summary Update user (Admin only)
// @Description Update an existing user's information and role
// @Tags users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param user body models.UpdateUserRequest true "User update data"
// @Security BearerAuth
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/users/{id} [put]
func (uc *UserController) UpdateUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid user ID format",
		})
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request format",
		})
		return
	}

	ctx := context.Background()

	// Get existing user
	var user models.User
	if err := uc.config.DB.NewSelect().Model(&user).Where("id = ?", userID).Scan(ctx); err != nil {
		if err.Error() == "sql: no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "User not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to fetch user",
			})
		}
		return
	}

	// Store original values for audit logging
	originalUser := user

	// Check if email/username conflicts with other users
	if req.Email != user.Email || req.Username != user.Username {
		var existingUser models.User
		if err := uc.config.DB.NewSelect().Model(&existingUser).
			Where("(email = ? OR username = ?) AND id != ?", req.Email, req.Username, userID).
			Scan(ctx); err == nil {
			c.JSON(http.StatusConflict, gin.H{
				"error":   "conflict",
				"message": "Email or username already exists",
			})
			return
		}
	}

	// Check if user is updating their own profile
	currentUserIDInterface, _ := c.Get("user_id")
	currentUserIDUint, _ := strconv.ParseUint(currentUserIDInterface.(string), 10, 32)
	isSelfUpdate := currentUserIDUint == userID

	// Update user fields
	user.Username = req.Username
	user.Name = req.Name
	user.Email = req.Email
	if req.PhoneNumber != nil {
		user.PhoneNumber = *req.PhoneNumber
	}

	// Only allow status and role updates if user has admin permissions (not self-update)
	if !isSelfUpdate {
		if req.Status != "" {
			user.Status = req.Status
		}
		if req.RoleID != nil && *req.RoleID != 0 {
			user.RoleID = *req.RoleID
		}
	}

	// Update password if provided
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to hash password",
			})
			return
		}
		user.Password = string(hashedPassword)
	}

	// Save updated user
	if _, err := uc.config.DB.NewUpdate().Model(&user).Where("id = ?", userID).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to update user",
		})
		return
	}

	// Create audit log for user update
	currentUserIDForAudit, _ := c.Get("user_id")
	var currentUser models.User
	if err := uc.config.DB.NewSelect().Model(&currentUser).Where("id = ?", currentUserIDForAudit).Scan(ctx); err == nil {
		// Track changes
		changes := make(map[string]*models.AuditChanges)

		if originalUser.Username != user.Username {
			changes["username"] = &models.AuditChanges{
				Before: originalUser.Username,
				After:  user.Username,
			}
		}
		if originalUser.Name != user.Name {
			changes["name"] = &models.AuditChanges{
				Before: originalUser.Name,
				After:  user.Name,
			}
		}
		if originalUser.Email != user.Email {
			changes["email"] = &models.AuditChanges{
				Before: originalUser.Email,
				After:  user.Email,
			}
		}
		if originalUser.PhoneNumber != user.PhoneNumber {
			changes["phone_number"] = &models.AuditChanges{
				Before: originalUser.PhoneNumber,
				After:  user.PhoneNumber,
			}
		}
		if originalUser.Status != user.Status {
			changes["status"] = &models.AuditChanges{
				Before: originalUser.Status,
				After:  user.Status,
			}
		}
		if originalUser.RoleID != user.RoleID {
			changes["role_id"] = &models.AuditChanges{
				Before: originalUser.RoleID,
				After:  user.RoleID,
			}
		}

		// Only create audit log if there were actual changes
		if len(changes) > 0 {
			ipAddress := c.ClientIP()
			userAgent := c.GetHeader("User-Agent")

			err = uc.auditController.CreateAuditLogWithUser(
				&currentUser,
				models.AuditActionUpdate,
				models.AuditEntityUser,
				strconv.Itoa(int(user.ID)),
				user.Email,
				"User profile updated",
				changes,
				ipAddress,
				userAgent,
			)
			if err != nil {
				// Log error but don't fail the update process
				// You might want to use a logger here
				// log.Printf("Failed to create audit log for user update: %v", err)
			}
		}
	}

	// Load the role for response
	if err := uc.config.DB.NewSelect().Model(&user).Relation("Role").Where("u.id = ?", user.ID).Scan(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to load updated user data",
		})
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// DeleteUser godoc
// @Summary Delete user (Admin only)
// @Description Delete a user from the system
// @Tags users
// @Produce json
// @Param id path int true "User ID"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/admin/users/{id} [delete]
func (uc *UserController) DeleteUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid user ID format",
		})
		return
	}

	ctx := context.Background()

	// Get existing user
	var user models.User
	if err := uc.config.DB.NewSelect().Model(&user).Where("id = ?", userID).Scan(ctx); err != nil {
		if err.Error() == "sql: no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "User not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "internal_error",
				"message": "Failed to fetch user",
			})
		}
		return
	}

	// Delete the user
	if _, err := uc.config.DB.NewDelete().Model(&user).Where("id = ?", userID).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to delete user",
		})
		return
	}

	// Create audit log for user deletion
	currentUserID, _ := c.Get("user_id")
	var currentUser models.User
	if err := uc.config.DB.NewSelect().Model(&currentUser).Where("id = ?", currentUserID).Scan(ctx); err == nil {
		ipAddress := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		changes := map[string]*models.AuditChanges{
			"username": {Before: user.Username},
			"name":     {Before: user.Name},
			"email":    {Before: user.Email},
			"status":   {Before: user.Status},
			"role_id":  {Before: user.RoleID},
		}

		err = uc.auditController.CreateAuditLogWithUser(
			&currentUser,
			models.AuditActionDelete,
			models.AuditEntityUser,
			strconv.Itoa(int(userID)),
			user.Email,
			"User account deleted",
			changes,
			ipAddress,
			userAgent,
		)
		if err != nil {
			// Log error but don't fail the deletion process
			// You might want to use a logger here
			// log.Printf("Failed to create audit log for user deletion: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}
