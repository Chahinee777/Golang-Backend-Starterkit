# Starterkit Backend API

High-performance RESTful API backend built with Go, Gin framework, and Bun ORM. Provides comprehensive user management, authentication, role-based access control, and audit logging for the React frontend application.

## 🚀 Features

- **RESTful API**: Clean and consistent API endpoints
- **High Performance**: Built with Go and Gin framework for optimal speed
- **Database ORM**: Bun ORM for type-safe database operations
- **Authentication**: JWT-based authentication system
- **Authorization**: Role-based access control (RBAC)
- **Audit Logging**: Comprehensive audit trail for all user actions
- **Security**: Password hashing, input validation, and SQL injection protection
- **Middleware**: Request logging, authentication, and permission checking
- **Database Migrations**: Automated database schema management

## 🛠️ Tech Stack

- **Language**: Go 1.21+
- **Web Framework**: Gin 1.9
- **ORM**: Bun 1.1
- **Database**: PostgreSQL 15+
- **Authentication**: JWT-Go 5.0
- **Password Hashing**: bcrypt
- **Database Driver**: PostgreSQL driver
- **Configuration**: Environment variables
- **Documentation**: Swagger/OpenAPI

## 📁 Project Structure

```
backend/
├── api/                    # Server setup and configuration
│   └── server.go          # Gin server initialization
├── config/                # Configuration files
│   ├── config.go          # Application configuration
│   └── rbac_migration.go  # Database migrations
├── controllers/           # HTTP request handlers
│   ├── auth_controller.go # Authentication endpoints
│   ├── user_controller.go # User management endpoints
│   ├── role_controller.go # Role management endpoints
│   └── audit_controller.go# Audit logging endpoints
├── db/                    # Database connection and setup
│   ├── db_wrapper.go      # Database wrapper
│   └── postgres.go        # PostgreSQL connection
├── middlewares/           # HTTP middlewares
│   ├── auth_middleware.go # JWT authentication
│   ├── logger_middleware.go# Request logging
│   ├── permission_middleware.go# RBAC permissions
│   └── request_id_middleware.go# Request ID tracking
├── models/                # Data models and structures
│   ├── user.go           # User model and methods
│   ├── role.go           # Role model and methods
│   └── audit.go          # Audit log model
├── routes/                # API route definitions
│   └── routes.go         # Route setup and grouping
├── utils/                 # Utility functions
│   ├── logger.go         # Logging utilities
│   ├── permissions.go    # Permission utilities
│   ├── response.go       # API response utilities
│   └── rest.go           # REST utilities
├── docs/                  # API documentation
│   ├── docs.go           # Swagger documentation
│   ├── swagger.json      # OpenAPI JSON
│   └── swagger.yaml      # OpenAPI YAML
├── main.go               # Application entry point
├── go.mod                # Go module dependencies
└── go.sum                # Dependency checksums
```

## 🚦 Getting Started

### Prerequisites

- Go 1.21 or higher
- PostgreSQL 15+ database
- Git for version control

### Installation

1. **Navigate to backend directory**:
   ```bash
   cd backend
   ```

2. **Install dependencies**:
   ```bash
   go mod tidy
   ```

3. **Set up environment variables**:
   Create a `.env` file in the backend directory:
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=5432
   DB_USER=your_username
   DB_PASSWORD=your_password
   DB_NAME=asteroidea_db
   DB_SSLMODE=disable

   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key-here
   JWT_EXPIRE_HOURS=24

   # Server Configuration
   PORT=8080
   GIN_MODE=debug
   ```

4. **Set up the database**:
   ```bash
   # Create PostgreSQL database
   createdb asteroidea_db

   # Run migrations
   go run config/rbac_migration.go
   ```

5. **Start the server**:
   ```bash
   go run main.go
   ```

   The API will be available at `http://localhost:8080`

## 🔌 API Endpoints

### Authentication
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | User login | No |
| POST | `/api/auth/refresh` | Refresh JWT token | Yes |
| POST | `/api/auth/logout` | User logout | Yes |

### User Management
| Method | Endpoint | Description | Auth Required | Permission |
|--------|----------|-------------|---------------|------------|
| GET | `/api/users` | List all users | Yes | `users:read` |
| GET | `/api/users/:id` | Get user by ID | Yes | `users:read` |
| POST | `/api/users` | Create new user | Yes | `users:create` |
| PUT | `/api/users/:id` | Update user | Yes | `users:update` |
| DELETE | `/api/users/:id` | Delete user | Yes | `users:delete` |

### Role Management
| Method | Endpoint | Description | Auth Required | Permission |
|--------|----------|-------------|---------------|------------|
| GET | `/api/roles` | List all roles | Yes | `roles:read` |
| GET | `/api/roles/:id` | Get role by ID | Yes | `roles:read` |
| POST | `/api/roles` | Create new role | Yes | `roles:create` |
| PUT | `/api/roles/:id` | Update role | Yes | `roles:update` |
| DELETE | `/api/roles/:id` | Delete role | Yes | `roles:delete` |

### Audit Logging
| Method | Endpoint | Description | Auth Required | Permission |
|--------|----------|-------------|---------------|------------|
| GET | `/api/audit` | List audit logs | Yes | `audit:read` |
| GET | `/api/audit/:id` | Get audit log by ID | Yes | `audit:read` |
| POST | `/api/audit` | Create audit log | Yes | `audit:create` |

## 🔒 Authentication & Authorization

### JWT Authentication
- JWT tokens are used for API authentication
- Tokens expire after 24 hours (configurable)
- Refresh tokens allow extending sessions
- Tokens include user ID and role information

### Role-Based Access Control (RBAC)
- Users are assigned roles (Admin, User, etc.)
- Roles have specific permissions
- Permissions control access to API endpoints
- Middleware automatically checks permissions

### Default Roles
- **Admin**: Full access to all resources
- **User**: Limited access to own profile and basic features

## 📊 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role_id INTEGER REFERENCES roles(id),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Roles Table
```sql
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Audit Logs Table
```sql
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(100),
    changes JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## 🧪 Testing

Run the test suite:
```bash
go test ./...
```

Run tests with coverage:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 🛡️ Security Features

- **Password Hashing**: bcrypt with salt
- **SQL Injection Protection**: Parameterized queries via Bun ORM
- **JWT Security**: Signed tokens with expiration
- **Input Validation**: Request validation and sanitization
- **CORS**: Configurable Cross-Origin Resource Sharing
- **Rate Limiting**: Request rate limiting (configurable)
- **Request Logging**: Comprehensive request/response logging

## 📈 Performance

- **Connection Pooling**: PostgreSQL connection pooling
- **Efficient Queries**: Optimized database queries
- **Gin Framework**: High-performance HTTP router
- **Minimal Memory**: Efficient memory usage
- **Concurrent Handling**: Go's goroutines for concurrent requests

## 🔧 Configuration

Environment variables for configuration:

```env
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=username
DB_PASSWORD=password
DB_NAME=database_name
DB_SSLMODE=disable

# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRE_HOURS=24

# Server
PORT=8080
GIN_MODE=release
CORS_ALLOWED_ORIGINS=http://localhost:3000

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

## 📋 API Response Format

All API responses follow a consistent format:

```json
{
  "message": "Success",
  "data": {
    // Response data here
  },
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 100,
    "total_pages": 10
  }
}
```

Error responses:
```json
{
  "error": "Error message",
  "details": "Detailed error information"
}
```

## 🚀 Deployment

### Docker Deployment
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]
```

### Production Setup
1. Build the binary: `go build -o asteroidea-api main.go`
2. Set production environment variables
3. Set up reverse proxy (nginx/Apache)
4. Configure SSL/TLS certificates
5. Set up process manager (systemd/PM2)

## 📚 API Documentation

- Swagger UI: `http://localhost:8080/swagger/index.html`
- OpenAPI JSON: `http://localhost:8080/swagger/doc.json`
- OpenAPI YAML: Available in `docs/swagger.yaml`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `go test ./...`
6. Commit changes: `git commit -m 'Add new feature'`
7. Push to branch: `git push origin feature/new-feature`
8. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Troubleshooting

### Common Issues

1. **Database Connection Error**:
   - Check PostgreSQL is running
   - Verify database credentials
   - Ensure database exists

2. **JWT Token Issues**:
   - Check JWT_SECRET is set
   - Verify token expiration settings
   - Ensure proper token format

3. **Permission Denied**:
   - Check user roles and permissions
   - Verify RBAC configuration
   - Check middleware order

### Getting Help

- Check the logs for detailed error messages
- Review the API documentation
- Check database migrations have run
- Verify environment variables are set correctly
