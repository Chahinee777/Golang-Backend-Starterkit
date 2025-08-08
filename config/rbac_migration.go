package config

import (
	"context"
	"fmt"

	"example.com/models"
	"github.com/uptrace/bun"
)

// MigrateRBAC creates the RBAC tables and migrates existing data
func MigrateRBAC(db *bun.DB) error {
	ctx := context.Background()

	// Create new tables
	if _, err := db.NewCreateTable().Model((*models.Module)(nil)).IfNotExists().Exec(ctx); err != nil {
		return fmt.Errorf("failed to create modules table: %w", err)
	}

	if _, err := db.NewCreateTable().Model((*models.Role)(nil)).IfNotExists().Exec(ctx); err != nil {
		return fmt.Errorf("failed to create roles table: %w", err)
	}

	if _, err := db.NewCreateTable().Model((*models.User)(nil)).IfNotExists().Exec(ctx); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create audit logs table
	if _, err := db.NewCreateTable().Model((*models.AuditLog)(nil)).IfNotExists().Exec(ctx); err != nil {
		return fmt.Errorf("failed to create audit_logs table: %w", err)
	}

	// Seed default modules
	if err := seedDefaultModules(db); err != nil {
		return fmt.Errorf("failed to seed default modules: %w", err)
	}

	// Seed default roles
	if err := seedDefaultRoles(db); err != nil {
		return fmt.Errorf("failed to seed default roles: %w", err)
	}

	// Migrate existing users to use role_id
	if err := migrateExistingUsers(db); err != nil {
		return fmt.Errorf("failed to migrate existing users: %w", err)
	}

	return nil
}

// seedDefaultModules creates the default modules
func seedDefaultModules(db *bun.DB) error {
	ctx := context.Background()
	modules := models.DefaultModules()

	for _, module := range modules {
		var existingModule models.Module
		err := db.NewSelect().Model(&existingModule).Where("name = ?", module.Name).Scan(ctx)

		if err != nil && err.Error() == "sql: no rows in result set" {
			if _, err := db.NewInsert().Model(&module).Exec(ctx); err != nil {
				return fmt.Errorf("failed to create module %s: %w", module.Name, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check module %s: %w", module.Name, err)
		}
	}

	return nil
}

// seedDefaultRoles creates the default roles with CRUD permissions
func seedDefaultRoles(db *bun.DB) error {
	ctx := context.Background()

	// Admin role with full permissions (granular format: view,create,edit,delete)
	adminPermissions := map[string]string{
		"users":     "1,1,1,1", // Full access
		"roles":     "1,1,1,1", // Full access
		"audit":     "1,0,0,0", // Read only
		"settings":  "1,0,1,0", // View and edit
		"dashboard": "1,0,0,0", // View only
	}

	// Manager role with management permissions
	managerPermissions := map[string]string{
		"users":     "1,1,1,0", // View, create, edit (no delete)
		"roles":     "1,0,0,0", // View only
		"audit":     "1,0,0,0", // View only
		"settings":  "1,0,0,0", // View only
		"dashboard": "1,0,0,0", // View only
	}

	// User role with limited permissions
	userPermissions := map[string]string{
		"users":     "0,0,0,0", // No access
		"roles":     "0,0,0,0", // No access
		"audit":     "0,0,0,0", // No access
		"settings":  "1,0,0,0", // View only
		"dashboard": "1,0,0,0", // View only
	}

	// Viewer role with read-only permissions
	viewerPermissions := map[string]string{
		"users":     "1,0,0,0", // View only
		"roles":     "1,0,0,0", // View only
		"audit":     "1,0,0,0", // View only
		"settings":  "1,0,0,0", // View only
		"dashboard": "1,0,0,0", // View only
	}

	roles := []struct {
		name        string
		description string
		permissions map[string]string
	}{
		{
			name:        "admin",
			description: "Administrator with full system access",
			permissions: adminPermissions,
		},
		{
			name:        "manager",
			description: "Manager with user management capabilities",
			permissions: managerPermissions,
		},
		{
			name:        "user",
			description: "Standard user with basic access",
			permissions: userPermissions,
		},
		{
			name:        "viewer",
			description: "Read-only access to selected modules",
			permissions: viewerPermissions,
		},
	}

	for _, roleData := range roles {
		var existingRole models.Role
		err := db.NewSelect().Model(&existingRole).Where("name = ?", roleData.name).Scan(ctx)

		if err != nil && err.Error() == "sql: no rows in result set" {
			role := models.Role{
				Name:        roleData.name,
				Description: roleData.description,
				IsActive:    true,
			}

			if err := role.SetPermissions(roleData.permissions); err != nil {
				return fmt.Errorf("failed to set permissions for role %s: %w", roleData.name, err)
			}

			if _, err := db.NewInsert().Model(&role).Exec(ctx); err != nil {
				return fmt.Errorf("failed to create role %s: %w", roleData.name, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check role %s: %w", roleData.name, err)
		}
	}

	return nil
}

// migrateExistingUsers updates existing users to use role_id
func migrateExistingUsers(db *bun.DB) error {
	ctx := context.Background()

	// Check if role_id column already exists and is populated
	count, err := db.NewSelect().Model((*models.User)(nil)).Where("role_id > 0").Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to count users with role_id: %w", err)
	}

	if count > 0 {
		// Migration already completed
		return nil
	}

	// Check if there are any users at all
	totalUsers, err := db.NewSelect().Model((*models.User)(nil)).Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to count total users: %w", err)
	}

	if totalUsers == 0 {
		// No users exist, migration not needed
		return nil
	}

	// Get role mappings
	var adminRole, userRole models.Role
	if err := db.NewSelect().Model(&adminRole).Where("name = ?", "admin").Scan(ctx); err != nil {
		return fmt.Errorf("admin role not found: %w", err)
	}
	if err := db.NewSelect().Model(&userRole).Where("name = ?", "user").Scan(ctx); err != nil {
		return fmt.Errorf("user role not found: %w", err)
	}

	// Check if the old 'role' column exists (for migration from old schema)
	var hasRoleColumn bool
	err = db.NewRaw("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'role')").Scan(ctx, &hasRoleColumn)
	if err != nil {
		return fmt.Errorf("failed to check for role column: %w", err)
	}

	if hasRoleColumn {
		// Update users with old string-based roles
		if _, err := db.NewRaw("UPDATE users SET role_id = ? WHERE role = ?", adminRole.ID, "admin").Exec(ctx); err != nil {
			return fmt.Errorf("failed to update admin users: %w", err)
		}

		if _, err := db.NewRaw("UPDATE users SET role_id = ? WHERE role = ? OR role = '' OR role IS NULL", userRole.ID, "user").Exec(ctx); err != nil {
			return fmt.Errorf("failed to update regular users: %w", err)
		}

		// Drop the old role column after migration
		if _, err := db.NewRaw("ALTER TABLE users DROP COLUMN IF EXISTS role").Exec(ctx); err != nil {
			return fmt.Errorf("failed to drop old role column: %w", err)
		}
	} else {
		// No old role column, but we have users without role_id set
		// Set all users to default user role
		if _, err := db.NewRaw("UPDATE users SET role_id = ? WHERE role_id = 0 OR role_id IS NULL", userRole.ID).Exec(ctx); err != nil {
			return fmt.Errorf("failed to set default role for users: %w", err)
		}
	}

	return nil
}
