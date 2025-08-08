package main

import (
	"example.com/controllers"
	"example.com/models"
)

// This file is used to import packages for Swagger generation
// It ensures that all the models and controllers are included in the documentation

var (
	_ = controllers.AuthController{}
	_ = models.User{}
	_ = models.RegisterRequest{}
	_ = models.LoginRequest{}
	_ = models.LoginResponse{}
	_ = models.UserResponse{}
)
