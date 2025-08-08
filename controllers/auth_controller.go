package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"example.com/config"
	"example.com/middlewares"
	"example.com/models"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	config          *config.Config
	auditController *AuditController
}

func NewAuthController(config *config.Config) *AuthController {
	return &AuthController{
		config:          config,
		auditController: NewAuditController(config),
	}
}

// Register godoc
// @Summary Register new user
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param user body models.RegisterRequest true "User registration data"
// @Success 201 {object} models.UserResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/auth/register [post]
func (ac *AuthController) Register(c *gin.Context) {
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
	if err := ac.config.DB.NewSelect().Model(&existingUser).Where("email = ? OR username = ?", req.Email, req.Username).Scan(ctx); err == nil {
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

	// Get default user role
	var defaultRole models.Role
	if err := ac.config.DB.NewSelect().Model(&defaultRole).Where("name = ?", "user").Scan(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Default role not found",
		})
		return
	}

	// Create user
	user := models.User{
		Username:    req.Username,
		Name:        req.Name,
		Email:       req.Email,
		Password:    string(hashedPassword),
		PhoneNumber: req.PhoneNumber,
		Status:      "active",
		RoleID:      defaultRole.ID,
	}

	if _, err := ac.config.DB.NewInsert().Model(&user).Exec(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to create user",
		})
		return
	}

	// Load the role for response
	if err := ac.config.DB.NewSelect().Model(&user).Relation("Role").Where("u.id = ?", user.ID).Scan(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to load user data",
		})
		return
	}

	c.JSON(http.StatusCreated, user.ToResponse())
}

// Login godoc
// @Summary User login
// @Description Authenticate user and return JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body models.LoginRequest true "User login credentials"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/auth/login [post]
func (ac *AuthController) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "bad_request",
			"message": "Invalid request data",
		})
		return
	}

	ctx := context.Background()

	// Find user by email with role and permissions
	var user models.User
	if err := ac.config.DB.NewSelect().Model(&user).Relation("Role").Where("u.email = ?", req.Email).Scan(ctx); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Invalid email or password",
		})
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Invalid email or password",
		})
		return
	}

	// Check if user is active
	if user.Status != "active" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Account is not active",
		})
		return
	}

	// Generate JWT token
	roleName := ""
	if user.Role != nil {
		roleName = user.Role.Name
	}
	token, err := middlewares.GenerateJWT(user.ID, user.Username, user.Email, roleName, ac.config.JWTSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to generate token",
		})
		return
	}

	// Log the login action
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	err = ac.auditController.CreateAuditLogWithUser(
		&user,
		models.AuditActionLogin,
		models.AuditEntitySession,
		"",
		"User login",
		"User successfully logged in",
		nil,
		ipAddress,
		userAgent,
	)
	if err != nil {
		// Log error but don't fail the login process
		// You might want to use a logger here
		// log.Printf("Failed to create audit log for login: %v", err)
	}

	// Return user data with permissions and token
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user.ToResponseWithPermissions(),
	})
}

// GetMe godoc
// @Summary Get current user profile
// @Description Get the profile of the currently authenticated user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.UserWithPermissions
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/auth/me [get]
func (ac *AuthController) GetMe(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User ID not found in token",
		})
		return
	}

	ctx := context.Background()
	var user models.User
	if err := ac.config.DB.NewSelect().Model(&user).Relation("Role").Where("u.id = ?", userID).Scan(ctx); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, user.ToResponseWithPermissions())
}

// Refresh godoc
// @Summary Refresh JWT token
// @Description Refresh an existing JWT token with a new one
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/auth/refresh [post]
func (ac *AuthController) Refresh(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "User ID not found in token",
		})
		return
	}

	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Username not found in token",
		})
		return
	}

	email, exists := c.Get("email")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Email not found in token",
		})
		return
	}

	role, exists := c.Get("role")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Role not found in token",
		})
		return
	}

	// Convert userID to uint
	var userIDUint uint
	switch v := userID.(type) {
	case string:
		// If userID is stored as string in JWT, parse it
		if parsed, err := strconv.ParseUint(v, 10, 32); err == nil {
			userIDUint = uint(parsed)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid user ID format",
			})
			return
		}
	case uint:
		userIDUint = v
	default:
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "Invalid user ID type",
		})
		return
	}

	// Generate new token
	token, err := middlewares.GenerateJWT(
		userIDUint,
		username.(string),
		email.(string),
		role.(string),
		ac.config.JWTSecret,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_error",
			"message": "Failed to generate token",
		})
		return
	}

	// Log the token refresh activity
	if ac.auditController != nil {
		err = ac.auditController.CreateSystemAuditLog(
			"token_refresh",
			models.AuditEntitySession,
			strconv.Itoa(int(userIDUint)),
			username.(string),
			fmt.Sprintf("JWT token refreshed for user %s", username.(string)),
			nil,
		)
		if err != nil {
			// Log error but don't fail the refresh process
			// You might want to use a logger here
			// log.Printf("Failed to create audit log for token refresh: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"token":   token,
		"message": "Token refreshed successfully",
	})
}
