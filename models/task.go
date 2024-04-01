// Package models contains the data models for the application to be used in request hanlding.
package models

// Task represents a task in the system.
// Task has the following properties:
// - Id: The unique identifier of the task.
// - Title: The title of the task.
// - Description: The description of the task.
// - Number: The number of task for finding fibonacci.
// - Result: The result of the fibonacci number.
// - Status: The status of the task.
type Task struct {
	Id          int    `json:"id"`
	Title       string `json:"title" validate:"required,min=3,max=50,fieldValidator"`
	Description string `json:"description" validate:"required,fieldValidator"`
	Number 		int    `json:"number" validate:"required"`
	Result		int    `json:"result"`
	Status      string `json:"status"`
}