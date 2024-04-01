// Package commands contains the commands for the application to be used for request inputs.
package commands

// DeleteTaskCommand represents a command to delete a task.
type DeleteTaskCommand struct {
	Id int `json:"id" validate:"required"`
}
