package models

// User represents a user in the system. User has a username, password, and role.
// Username and password are required fields.
// role is assigned to the user.
type User struct {
	Username string `json:"username" validate:"required`
	Password string `json:"password" validate:"required`
	Role string `json: "role"`
}