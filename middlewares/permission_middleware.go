package middlewares

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"example.com/config"
	"example.com/models"
	"example.com/utils"
	"github.com/gin-gonic/gin"
)

// hasGranularPermission checks if user has permission for a specific action using granular format
func hasGranularPermission(permissions map[string]string, module string, action string) bool {
	permissionString, exists := permissions[module]
	if !exists || permissionString == "" {
		return false
	}

	// Parse granular permission string "1,1,1,1" (view,create,edit,delete)
	parts := strings.Split(permissionString, ",")
	if len(parts) != 4 {
		return false
	}

	switch action {
	case "read", "view":
		return strings.TrimSpace(parts[0]) == "1"
	case "create":
		return strings.TrimSpace(parts[1]) == "1"
	case "update", "edit":
		return strings.TrimSpace(parts[2]) == "1"
	case "delete":
		return strings.TrimSpace(parts[3]) == "1"
	default:
		return false
	}
}

// RequirePermission creates middleware that checks if user has required permission for a module and action
func RequirePermission(config *config.Config, module string, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from JWT claims
		userIDStr, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "User ID not found in token",
			})
			c.Abort()
			return
		}

		// Convert user ID to uint
		userID, err := strconv.ParseUint(userIDStr.(string), 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "Invalid user ID format",
			})
			c.Abort()
			return
		}

		// Fetch user with role and permissions
		ctx := context.Background()
		var user models.User
		if err := config.DB.NewSelect().Model(&user).Relation("Role").Where("u.id = ?", userID).Scan(ctx); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "User not found",
			})
			c.Abort()
			return
		}

		// Get user permissions in new granular format
		granularPermissions := user.Role.GetGranularPermissions()

		// Check if user has required permission using granular format
		if !hasGranularPermission(granularPermissions, module, action) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "Insufficient permissions for this action",
				"details": map[string]interface{}{
					"required_module": module,
					"required_action": action,
					"user_permission": granularPermissions[module],
				},
			})
			c.Abort()
			return
		}

		// Store granular permissions in context for use in controllers
		c.Set("user_permissions", granularPermissions)
		c.Next()
	}
}

// RequireModuleRead middleware for read operations
func RequireModuleRead(config *config.Config, module string) gin.HandlerFunc {
	return RequirePermission(config, module, "read")
}

// RequireModuleCreate middleware for create operations
func RequireModuleCreate(config *config.Config, module string) gin.HandlerFunc {
	return RequirePermission(config, module, "create")
}

// RequireModuleUpdate middleware for update operations
func RequireModuleUpdate(config *config.Config, module string) gin.HandlerFunc {
	return RequirePermission(config, module, "update")
}

// RequireModuleDelete middleware for delete operations
func RequireModuleDelete(config *config.Config, module string) gin.HandlerFunc {
	return RequirePermission(config, module, "delete")
}

// GetPermissionCheckerFromContext extracts the permission checker from gin context (legacy)
func GetPermissionCheckerFromContext(c *gin.Context) *utils.PermissionChecker {
	if pc, exists := c.Get("permission_checker"); exists {
		if permissionChecker, ok := pc.(*utils.PermissionChecker); ok {
			return permissionChecker
		}
	}
	return nil
}

// GetGranularPermissionsFromContext extracts granular permissions from gin context
func GetGranularPermissionsFromContext(c *gin.Context) map[string]string {
	if permissions, exists := c.Get("user_permissions"); exists {
		if granularPermissions, ok := permissions.(map[string]string); ok {
			return granularPermissions
		}
	}
	return make(map[string]string)
}

// GetUserPermissionsFromContext extracts user permissions map from gin context
func GetUserPermissionsFromContext(c *gin.Context) map[string]int {
	if perms, exists := c.Get("user_permissions"); exists {
		if permissions, ok := perms.(map[string]int); ok {
			return permissions
		}
	}
	return make(map[string]int)
}

// RequireUserUpdateOrSelf middleware for user update operations that allows self-updates
func RequireUserUpdateOrSelf(config *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from JWT claims
		userIDStr, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "User ID not found in token",
			})
			c.Abort()
			return
		}

		// Convert user ID to uint
		currentUserID, err := strconv.ParseUint(userIDStr.(string), 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "Invalid user ID format",
			})
			c.Abort()
			return
		}

		// Get target user ID from URL parameter
		targetUserIDStr := c.Param("id")
		targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "bad_request",
				"message": "Invalid target user ID format",
			})
			c.Abort()
			return
		}

		// If user is updating their own profile, allow it
		if currentUserID == targetUserID {
			c.Next()
			return
		}

		// If not updating self, check for users:update permission
		ctx := context.Background()
		var user models.User
		if err := config.DB.NewSelect().Model(&user).Relation("Role").Where("u.id = ?", currentUserID).Scan(ctx); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "User not found",
			})
			c.Abort()
			return
		}

		// Get user permissions in granular format
		granularPermissions := user.Role.GetGranularPermissions()

		// Check if user has required permission for updating other users
		if !hasGranularPermission(granularPermissions, "users", "update") {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "Insufficient permissions to update other users",
				"details": map[string]interface{}{
					"required_module": "users",
					"required_action": "update",
					"user_permission": granularPermissions["users"],
				},
			})
			c.Abort()
			return
		}

		// Store granular permissions in context for use in controllers
		c.Set("user_permissions", granularPermissions)
		c.Next()
	}
}
