package routes

import (
	"time"

	"example.com/config"
	"example.com/controllers"
	"example.com/middlewares"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRoutes(r *gin.Engine, config *config.Config) {
	// CORS middleware
	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"}, // In production, specify exact origins
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           time.Duration(config.CORSMaxAge) * time.Hour,
	}
	r.Use(cors.New(corsConfig))

	// Initialize controllers
	authController := controllers.NewAuthController(config)
	userController := controllers.NewUserController(config)
	roleController := controllers.NewRoleController(config)
	auditController := controllers.NewAuditController(config)

	// API routes
	api := r.Group(config.APIURL)
	{
		// Public routes
		api.POST("/register", authController.Register)
		api.POST("/login", authController.Login)

		// Protected routes
		protected := api.Group("/")
		protected.Use(middlewares.AuthMiddleware(config))
		{
			protected.GET("/me", authController.GetMe)
			protected.GET("/profile", authController.GetMe)    // Add profile alias for frontend compatibility
			protected.POST("/refresh", authController.Refresh) // Add refresh token endpoint

			// User routes (self-access or with permissions)
			protected.GET("/users/:id", middlewares.RequireModuleRead(config, "users"), userController.GetUser)
			protected.PUT("/users/:id", middlewares.RequireUserUpdateOrSelf(config), userController.UpdateUser)
		}

		// Admin routes - access controlled by permissions, not role
		admin := api.Group("/admin")
		admin.Use(middlewares.AuthMiddleware(config))
		{
			// User management with permission checks
			admin.GET("/users", middlewares.RequireModuleRead(config, "users"), userController.GetAllUsers)
			admin.POST("/users", middlewares.RequireModuleCreate(config, "users"), userController.CreateUser)
			admin.DELETE("/users/:id", middlewares.RequireModuleDelete(config, "users"), userController.DeleteUser)

			// Role management with permission checks
			admin.GET("/roles", middlewares.RequireModuleRead(config, "roles"), roleController.GetAllRoles)
			admin.GET("/roles/:id", middlewares.RequireModuleRead(config, "roles"), roleController.GetRole)
			admin.POST("/roles", middlewares.RequireModuleCreate(config, "roles"), roleController.CreateRole)
			admin.PUT("/roles/:id", middlewares.RequireModuleUpdate(config, "roles"), roleController.UpdateRole)
			admin.DELETE("/roles/:id", middlewares.RequireModuleDelete(config, "roles"), roleController.DeleteRole)

			// Audit management with permission checks
			admin.GET("/audit-logs", middlewares.RequireModuleRead(config, "audit"), auditController.GetAuditLogs)
			admin.GET("/audit-logs/:id", middlewares.RequireModuleRead(config, "audit"), auditController.GetAuditLogById)
			admin.POST("/audit-logs", middlewares.RequireModuleCreate(config, "audit"), auditController.CreateAuditLog)

			// User-specific audit logs
			admin.GET("/users/:userId/audit-logs", middlewares.RequireModuleRead(config, "audit"), auditController.GetUserAuditLogs)
		}
	}

	// Swagger documentation (if enabled)
	if config.SwaggerEnabled {
		r.GET(config.SwaggerPath+"/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "ok",
			"timestamp": time.Now().UTC(),
		})
	})
}
