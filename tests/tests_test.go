// Package tests contains unit tests for the KonzekWebService application.
//
// This package contains unit tests for the KonzekWebService application.
// It includes tests for various handlers such as LoginHandler, CreateTaskHandler, GetTaskHandler, GetAllTaskHandler,
// UpdateTaskHandler, and DeleteTaskHandler. These tests ensure that the handlers function correctly and return the expected results.
package tests

import (
	"KonzekWebService/models"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

var (
	// client is the HTTP client used to make requests
	client = &http.Client{}
)

func loginuser(user string, password string) (string, error) {	
	loginReequestBody := map[string]interface{}{
		"username":       user,
		"password": password,
	}
	loginBodyBytes, err := json.Marshal(loginReequestBody)
	if err != nil {
		return "", err
	}
	reqlogin, err := http.NewRequest("POST", "http://localhost:8080/task/login", bytes.NewBuffer(loginBodyBytes))
	if err != nil {
		return "", err
		
	}
	reqlogin.Header.Set("Content-Type", "application/json")
	tokenResponse, err := client.Do(reqlogin)
	if err != nil {
		return "", err
	}
	defer tokenResponse.Body.Close()

	var tokenBody map[string]interface{}
	err = json.NewDecoder(tokenResponse.Body).Decode(&tokenBody)
	if err != nil {
		return "", err

	}
	return tokenBody["token"].(string), nil
}
// TestLoginHandler is a unit test function that tests the LoginHandler function.
// It sends a POST request to the login endpoint with a username and password,
// and checks if the response status code is HTTP 200 OK. 
func TestLoginHandler(t *testing.T) {
	
	requestBody := map[string]interface{}{
		"username":       "linda",
		"password": "123456",
	}

	// Marshal the request body into JSON
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Error marshaling request body: %v", err)
	}
	
	req, err := http.NewRequest("POST", "http://localhost:8080/task/login", bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		t.Fatalf("Error creating HTTP request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error making POST request: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
	}
	defer response.Body.Close()
	
	var responsetoken map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responsetoken)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	token, ok := responsetoken["token"].(string)
	if !ok {
		t.Error("Token field not found or not a string")
	}
	if token == "" {
		t.Error("unauthorized user")
	}
}

// TestCreateTaskHandler is a unit test function that tests the CreateTaskHandler function.
// It sends a POST request to the create endpoint with a task title, description, status,
// and checks if the response status code is HTTP 200 OK.
// 
func TestCreateTaskHandler(t *testing.T) {
	
	requestBody := map[string]interface{}{
		"title":       "Task 3 title",
		"description": "Task 3 description",
		"number":      10,
		"result":      0,
		"status":      "created",
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Error marshaling request body: %v", err)
	}
	req, err := http.NewRequest("POST", "http://localhost:8080/task/create", bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		t.Fatalf("Error creating HTTP request: %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	username := "user1"
	password := "09876"
	token, err := loginuser(username, password)
	if err != nil {
		t.Fatalf("Error logging in user: %v", err)
	}
	req.Header.Add("Authorization", token)
	response, err := client.Do(req)
		if err != nil {
		t.Fatalf("Error making POST request: %v", err)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
	}
	defer response.Body.Close()

	var responseBody map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	id, exists := responseBody["id"]
	if !exists{
		t.Error("id must be non-zero")
	}
	title, ok := responseBody["title"].(string)
	if !ok {
		t.Error("Title field not found or not a string")
	}
	description, ok := responseBody["description"].(string)
	if !ok {
		t.Error("Description field not found or not a string")
	}
	number, ok := responseBody["number"].(int)
	if !ok {
		t.Error("Number field not found or not an int")
	}
	result, ok := responseBody["result"].(int)
	if !ok {
		t.Error("Result field not found or not an int")
	}
	status, ok := responseBody["status"].(string)
	if !ok {
		t.Error("Status field not found or not a string")
	}
	if id == 0 && title == "Task 3 title" && description == "Task 3 description" && number == 10 && result == 0 && status == "created" {
		t.Errorf("Expected id: 1, title: Task 3 title, description: Task 3 description, number: 10, result: 0, status: created, got id: %d, title: %s, description: %s, number: %d, result: %d, status: %s", id, title, description, number, result, status)
	}
}

// TestUpdateTaskHandler is a unit test function that tests the functionality of the UpdateTaskHandler.
// It sends a POST request to the server with a JSON payload representing a task update,
// and then checks the response for correctness and and checks if the response status code is HTTP 200 OK.
// TestUpdateTaskHandler tests the UpdateTaskHandler function.
// It sends a POST request to the update endpoint with a task update payload,
// and checks if the response status code is HTTP 200 OK.
// It also checks if the request body is equal to the response body.
func TestUpdateTaskHandler(t *testing.T) {
	requestBody := map[string]interface{}{
		"id":          1,
		"Title":       "Task 1 title updated",
		"Description": "Task 1 description updated",
		"Number":      3,
		"Result":      0,
		"Status":      "created",
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Error marshaling request body: %v", err)
	}
		req, err := http.NewRequest("POST", "http://localhost:8080/task/update", strings.NewReader(string(requestBodyBytes)))
		if err != nil {
	        t.Fatalf("Error creating HTTP request: %v", err)
	    }
		req.Header.Set("Content-Type", "application/json")
		token, err := loginuser("user1", "09876")
		if err != nil {
			t.Fatalf("Error getting token: %v", err)
		}
		req.Header.Set("Authorization", token)
		
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("Error making POST request: %v", err)
		}
		if response.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
		}
	defer response.Body.Close()

	var responseBody map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	id, exists := responseBody["id"]
	if !exists{
		t.Error("id must be non-zero")
	}
	title, ok := responseBody["title"].(string)
	if !ok {
		t.Error("Title field not found or not a string")
	}
	description, ok := responseBody["description"].(string)
	if !ok {
		t.Error("Description field not found or not a string")
	}
	number, ok := responseBody["number"].(int)
	if !ok {
		t.Error("Number field not found or not an int")
	}
	result, ok := responseBody["result"].(int)
	if !ok {
		t.Error("Result field not found or not an int")
	}
	status, ok := responseBody["status"].(string)
	if !ok {
		t.Error("Status field not found or not a string")
	}
	if id != 1 && title != "Task 1 title updated" && description != "Task 1 description updated" && number != 3 && result != 0 && status != "created" {
		t.Errorf("Expected id: 1, title: Task 1 title updated, description: Task 1 description updated, number: 3, result: 0, status: created, got id: %d, title: %s, description: %s, number: %d, result: %d, status: %s", id, title, description, number, result, status)	
	}
}

// TestGetTaskHandler is a unit test function that tests the GetTaskHandler function.
// It sends a GET request to the getid endpoint with a task id,
// and checks if the response status code is HTTP 200 OK.
//
// replace the approperiate user/admin tokens in the request header.
func TestGetTaskHandler(t *testing.T) {
	
	req, err := http.NewRequest("GET", "http://localhost:8080/task/getid/1", nil)
	if err != nil {
		t.Fatalf("Error creating HTTP request: %v\n", err)
		return
	}
	token, err := loginuser("user1", "09876")
	if err != nil {
		t.Fatalf("Error getting token: %v", err)
	}
	req.Header.Set("Authorization", token)	

	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error making GET request: %v", err)
	}
	defer response.Body.Close()
	var responseBody map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	id, exists := responseBody["id"]
	if !exists{
		t.Error("id must be non-zero")
	}
	title, ok := responseBody["title"].(string)
	if !ok {
		t.Error("Title field not found or not a string")
	}
	description, ok := responseBody["description"].(string)
	if !ok {
		t.Error("Description field not found or not a string")
	}
	number, ok := responseBody["number"].(int)
	if !ok {
		t.Error("Number field not found or not an int")
	}
	result, ok := responseBody["result"].(int)
	if !ok {
		t.Error("Result field not found or not an int")
	}
	status, ok := responseBody["status"].(string)
	if !ok {
		t.Error("Status field not found or not a string")
	}
	if status != "created" && status != "completed" && id != 1 && title != "Task 1 title updated" && description != "Task 1 description updated" && number != 3 && result != 0 {
		t.Errorf("Expected id: 1, title: Task 1 title updated, description: Task 1 description updated, number: 3, result: 0, status: created, got id: %d, title: %s, description: %s, number: %d, result: %d, status: %s", id, title, description, number, result, status)
	}
}

// TestGetAllTaskHandler is a unit test function that tests the GetTaskHandler for getAll function.
// It sends a POST request to the getAll endpoint, and checks if the response status code is HTTP 200 OK.
//
// It checks the response body to ensure that all tasks are returned in an list of tasks.
func TestGetAllTaskHandler(t *testing.T) {
	req, err := http.NewRequest("POST", "http://localhost:8080/task/getAll", nil)
	if err != nil {
        t.Fatalf("Error creating HTTP request: %v", err)
    }
	req.Header.Set("Content-Type", "application/json")

	token, err := loginuser("linda", "123456")
	if err != nil {
		t.Fatalf("Error getting token: %v", err)
	}
	req.Header.Set("Authorization", token)
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error making POST request: %v", err)
	}
	if err != nil {
		t.Fatalf("Error making POST request: %v", err)
	}

	defer response.Body.Close()
	var tasks []models.Task
	err = json.NewDecoder(response.Body).Decode(&tasks)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
	}
	
}

// TestGetAllTaskPaginationkHandler is a unit test function that tests the GetTaskHandler for getAll function with pagination.
// It sends a POST request to the getAll endpoint with pagination parameters, and checks if the response status code is HTTP 200 OK.
//
// It checks the response body to ensure that the correct number of tasks are returned based on the pagesize parameter for pagination.
// To test this, replace the admin token in the request header.
func TestGetAllTaskPaginationkHandler(t *testing.T) {
	req, err := http.NewRequest("POST", "http://localhost:8080/task/getAll?page=1&pagesize=5", nil)
	if err != nil {
        t.Fatalf("Error creating HTTP request: %v", err)
    }
	req.Header.Set("Content-Type", "application/json")

	token, err := loginuser("linda", "123456")
	if err != nil {
		t.Fatalf("Error getting token: %v", err)
	}
	req.Header.Set("Authorization", token)
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error making POST request: %v", err)
	}
	if err != nil {
		t.Fatalf("Error making POST request: %v", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
	}
	var tasks []models.Task
	err = json.NewDecoder(response.Body).Decode(&tasks)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
	if len(tasks) != 5 {
		t.Errorf("Expected 10 tasks, got %d tasks", len(tasks))
	}
}

// TestDeleteTaskHandler tests the DeleteTaskHandler function.
// It sends a POST request to the delete endpoint with a task id,
// and checks if the response status code is HTTP 200 OK.
//
func TestDeleteTaskHandler(t *testing.T) {

	requestBody := map[string]interface{}{
		"id": 3,
	}
	// Marshal the request body into JSON
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("Error marshaling request body: %v", err)
	}

	req, err := http.NewRequest("POST", "http://localhost:8080/task/delete", strings.NewReader(string(requestBodyBytes)))
	if err != nil {
        t.Fatalf("Error creating HTTP request: %v", err)
    }
	req.Header.Set("Content-Type", "application/json")
	token, err := loginuser("linda", "123456")
	if err != nil {
		t.Fatalf("Error getting token: %v", err)
	}
	req.Header.Set("Authorization", token)
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error making POST request: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, response.StatusCode)
	}
	defer response.Body.Close()
	var responseBody map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
}