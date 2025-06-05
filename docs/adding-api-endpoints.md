# Developer Onboarding Guide: Adding API Endpoints

This guide walks through the process of adding new API endpoints to the cservice-api project, following the existing patterns and architecture.

## Architecture Overview

The cservice-api follows a layered architecture with clear separation of concerns:

1. **Routes** - Define API endpoints and HTTP method handlers
2. **Controllers** - Process requests, implement business logic, and format responses
3. **Models** - Database operations using SQLC-generated code
4. **Database** - SQL queries and schema migrations

## Prerequisites

Before adding a new endpoint, ensure you understand:

- Go programming language basics
- Echo framework for API development
- SQLC for generating type-safe Go code from SQL

## Step-by-Step Guide to Adding an API Endpoint

### 1. Define SQL Queries

First, you need to define the SQL queries that your endpoint will use.

1. Create or update a SQL file in `db/queries/` directory with your new queries
2. Follow the SQLC comment syntax to name your queries and specify their return types

Example (`db/queries/example.sql`):

```sql
-- name: GetExample :one
SELECT * FROM example_table
WHERE id = $1 LIMIT 1;

-- name: ListExamples :many
SELECT * FROM example_table
ORDER BY id;

-- name: CreateExample :one
INSERT INTO example_table (name, description)
VALUES ($1, $2)
RETURNING *;
```

The comments above each query are critical:

- `:one` indicates the query returns a single row
- `:many` indicates the query returns multiple rows
- `:exec` indicates the query doesn't return any rows

### 2. Generate Go Code with SQLC

After defining your SQL queries, generate the corresponding Go code:

```bash
make sqlc
```

This will generate Go code in the `models/` directory based on your SQL queries, including:

- Strongly typed parameter structs
- Result structs
- Interface methods

### 3. Create or Update a Controller

Controllers handle the business logic for your endpoints. Create a new controller or extend an existing one in the `controllers/` directory.

Example (`controllers/example.go`):

```go
package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/internal/helper"
	"github.com/undernetirc/cservice-api/models"
)

// ExampleController contains methods for example endpoints
type ExampleController struct {
	s models.Querier
}

// NewExampleController creates a new ExampleController
func NewExampleController(s models.Querier) *ExampleController {
	return &ExampleController{s: s}
}

// ExampleResponse defines the JSON response structure
type ExampleResponse struct {
	ID          int32  `json:"id"          extensions:"x-order=0"`
	Name        string `json:"name"        extensions:"x-order=1"`
	Description string `json:"description" extensions:"x-order=2"`
}

// GetExample returns an example by ID
// @Summary Get example by ID
// @Description Returns an example resource by its ID
// @Tags examples
// @Produce json
// @Param id path int true "Example ID"
// @Success 200 {object} ExampleResponse
// @Failure 400 {string} string "Invalid ID format"
// @Failure 404 {string} string "Example not found"
// @Router /examples/{id} [get]
// @Security JWTBearerToken
func (ctr *ExampleController) GetExample(c echo.Context) error {
	id, err := helper.SafeAtoi32(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid ID format")
	}

	example, err := ctr.s.GetExample(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "Example not found")
	}

	response := &ExampleResponse{
		ID:          example.ID,
		Name:        example.Name,
		Description: example.Description,
	}

	return c.JSON(http.StatusOK, response)
}
```

Key points:

- Controllers receive the models.Querier interface through dependency injection
- Response structures typically differ from database model structures
- Use swagger/openapi annotations for API documentation
- Follow the pattern of returning appropriate HTTP status codes

### 4. Define Routes

Routes connect HTTP endpoints to controller methods. Add your new routes in the `routes/` directory.

Example (`routes/example.go`):

```go
package routes

import (
	"github.com/labstack/gommon/log"
	"github.com/undernetirc/cservice-api/controllers"
	"github.com/undernetirc/cservice-api/middlewares"
)

// ExampleRoutes defines the routes for example endpoints
func (r *RouteService) ExampleRoutes() {
	log.Info("Loading example routes")
	c := controllers.NewExampleController(r.service)

	// Create a route group with optional middleware
	router := r.routerGroup.Group("/examples", middlewares.HasAuthorization(1000))

	// Define routes and HTTP methods
	router.GET("", c.ListExamples)
	router.GET("/:id", c.GetExample)
	router.POST("", c.CreateExample)
	router.PUT("/:id", c.UpdateExample)
	router.DELETE("/:id", c.DeleteExample)
}
```

Important:

- Route method name must end with `Routes` to be automatically loaded
- Routes can have middleware for authentication, authorization, etc.
- Group related endpoints under a common path prefix

### 5. Update the Router Registration

The `routes.go` file uses reflection to automatically find and register all route methods. If your new routes follow the naming convention (ending with `Routes`), they will be registered automatically.

However, if you're adding an entirely new feature area, make sure:

1. Your route method name ends with `Routes` (e.g., `ExampleRoutes`)
2. It's exported (capitalized)
3. It's defined as a method on the `RouteService` struct

### 6. Testing Your API Endpoint

Create corresponding test files for your controllers and routes:

- `controllers/example_test.go` - Unit tests for controller logic
- `routes/example_test.go` - Integration tests for HTTP endpoints

Follow the existing test patterns in the codebase for consistency.

## Best Practices

### SQL and Database

1. Use parameterized queries to prevent SQL injection
2. Add database migrations in `db/migrations/` for schema changes
3. Keep SQL queries simple and focused
4. Follow naming conventions in existing query files

### Controllers

1. Validate all input parameters
2. Return appropriate HTTP status codes
3. Use structured error responses
4. Document all endpoints with swagger annotations
5. Keep controllers focused on request/response handling

### Routes

1. Group related endpoints
2. Apply appropriate middleware for auth/validation
3. Use descriptive route paths
4. Follow REST conventions for resource naming

### General

1. Follow the existing code style and patterns
2. Write tests for new functionality
3. Use dependency injection for easier testing
4. Document public functions and types

## Example Workflow

Here's a complete workflow for adding a new "notes" feature:

1. Define SQL queries in `db/queries/notes.sql`
2. Generate code with `make sqlc`
3. Create `controllers/notes.go`
4. Create `routes/notes.go`
5. Test the endpoints with curl or Postman
6. Add tests in `controllers/notes_test.go` and `routes/notes_test.go`

## Troubleshooting

- **SQLC errors**: Check SQL syntax and SQLC annotations
- **Route not found**: Ensure route method ends with `Routes` and is registered
- **Middleware issues**: Verify middleware order and configuration
- **Database errors**: Check connection settings in config.yml

For more help, refer to the project documentation or ask the development team.
