// Package handlers provides the HTTP request handlers for KonzekWebService.
//
// This package contains the implementation of various HTTP request handlers for handling tasks (CRUD operations) in the KonzekWebService application.
// It includes handlers for task creation, retrieval, update, and deletion, as well as authentication and authorization handlers.
// The handlers interact with a MySQL database to perform CRUD operations on tasks and use JWT tokens for authentication and authorization.
// The package also includes utility functions for validating task fields and sanitizing task data to prevent XSS attacks.
// The handlers are designed to be used in a web server application that exposes RESTful APIs for managing tasks.
//
// For more information on how to use the handlers and the available endpoints, please refer to the individual handler function documentation.
// Package handlers provides the HTTP request handlers for .
package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"sync"
	"time"

	"KonzekWebService/commands"
	"KonzekWebService/models"
	"KonzekWebService/response"
	"KonzekWebService/validation"
	"strconv"
	"strings"

	"github.com/go-playground/validator"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var (
	db          *sql.DB
	workerCount = 5 // Number of worker goroutines in the pool
	taskChan    = make(chan models.Task, workerCount)
	create_lock = sync.Mutex{}
	log = logrus.New()
	secretKey = []byte(os.Getenv("SECRET_KEY"))
	validate    = validator.New()	
)

func Initialize() {
	
	validate.RegisterValidation("fieldValidator", validator.Func(func(fl validator.FieldLevel) bool {
		return validation.FieldValidator(fl) // Register custom validator
	}))
	validate.RegisterValidation("statusValidator", validator.Func(func(fl validator.FieldLevel) bool {
		return validation.StatusValidator(fl)
	}))

	log.SetLevel(logrus.InfoLevel)
	log.SetFormatter(&logrus.JSONFormatter{})

	cfg := mysql.Config{
		User:   os.Getenv("DB_USERNAME"),
		Passwd: os.Getenv("DB_PASSWORD"),
		Net:    "tcp",
		Addr:   os.Getenv("DB_ADDRESS")+":3307",
		DBName: "taskdb",
		AllowNativePasswords: true,
	}
	var err error
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}
	
	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}
	fmt.Println("Connected!")
}

// sanitizeTask sanitizes the task fields to prevent XSS attacks.
func sanitizeTask(task *models.Task) {
	task.Title = html.EscapeString(strings.TrimSpace(task.Title))
	task.Description = html.EscapeString(strings.TrimSpace(task.Description))
	task.Status = html.EscapeString(strings.TrimSpace(task.Status))
}

// To simulate a concurrent mechanism task execution, I create a worker pool of goroutines that execute tasks concurrently. 
func fib(n int) int {
	if n <= 0 {
		return 0
		} else if n == 1 {
			return 1
			} else { 
				return fib(n-1) + fib(n-2)
	}
}

// worker executes the task queued to channel and updates its status with the result.
// The worker function calculates the fibonacci number given the number specified in the "number" field in the request body
// then updates the task status and result in the response body.
func worker(task *models.Task) {
	fmt.Println(task.Title, "is being executed id", task.Id)
	task.Status = "in progress"
	UpdateTask(task)
	res := fib(task.Number)
	fmt.Println(task.Title, "is completed! id", task.Id, "result", res)
	task.Status = "completed" 
	task.Result = res
	UpdateTask(task)
}

// VerifyToken verifies the validity of a JWT token and extracts the role from its claims.
// It takes a token string as input and returns the role as a string if the token is valid and contains the role claim.
// If the token is invalid or does not contain the role claim, it returns an error.
func VerifyToken(tokenString string) (string, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte(secretKey), nil
    })
    if err != nil {
        return "", err
    }
    if !token.Valid {
        return "", fmt.Errorf("invalid token")
    }
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        if role, ok := claims["Role"].(string); ok {
            return role, nil
        }
        return "", fmt.Errorf("role not found in token claims")
    }

    return "", fmt.Errorf("invalid token claims")
}

// AuthorizeHandler is a handler function that authorizes the request based on the provided token.
// It checks the "Authorization" header in the request for a valid token and verifies it.
// If the token is missing or invalid, it returns an error and sends an appropriate response to the client.
// If the token is valid, it returns the role associated with the token.
//
// Returns:
// - string: The role associated with the token.
// - error: An error if the authorization token is missing or invalid.
func AuthorizeHandler(res http.ResponseWriter, req *http.Request) (string, error) {
	res.Header().Set("Content-Type", "application/json")
	tokenString := req.Header.Get("Authorization")
	if tokenString == "" {
		res.WriteHeader(http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": "authorizting user",
			}).Error("unauthorized user")
		return "", fmt.Errorf("missing authorization header")
	}
	tokenString = tokenString[len("Bearer "):]

		role, err := VerifyToken(tokenString)
	if err != nil {
		res.WriteHeader(http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": "authorizting user",
			}).Error("invadlid token")
		return "",err
	}
	log.WithFields(logrus.Fields{
		"task operation": "authorizting user",
		}).Info("processing authorization")
	return role, nil
}

// CreateToken generates a JWT token with the given username and role.
// The token is signed using the HS256 algorithm and includes an expiration time of 24 hours.
// It returns the generated token string in the format "Bearer <token>".
// If there is an error during token generation, it returns an empty string and the error.
// 
// Returns:
// - string: The generated token string in the format "Bearer <token>".
// - error: An error if the token generation fails.
func CreateToken(username string, role string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, 
		jwt.MapClaims{ 
		"username": username, 
		"Role":     role,
		"exp": time.Now().Add(time.Hour * 24).Unix(), 
		})

		tokenString, err := token.SignedString(secretKey)
		if err != nil {
		return "", err
		}
   
	return "Bearer "+ tokenString, nil
}

// LoginHandler handles the login request and generates a token for authorized users.
// It keeps track of the number of requests or errors using Prometheus counters.
// It accesses the request body with the username and password of the user.
// 
// Example request body:
// {
//   "username": "admin",
//   "password": "admin"
// }
//
// If the credentials are invalid, an error is logged and the response status is set to Unauthorized.
// If the user is authorized, the response status is set to OK and the token is logged then sent to user in the response body.
// 
// To test the following handlers, you can use the following credentials:-
// 
// Admin credentials are:
// - Username: linda
// - Password: 123456
// 
// User credentials are:
// - Username: user1
// - Password: 09876
func LoginHandler(res http.ResponseWriter, req *http.Request, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec) {
	var (
		tokenString string
		err error
		authorized bool
		u models.User
	)
	endPointCounter.WithLabelValues("/task/login").Inc()
	res.Header().Set("Content-Type", "application/json")
	json.NewDecoder(req.Body).Decode(&u)
	log.Infof("The user request value %v", u)
	
	if u.Username == os.Getenv("USER_USERNAME_NORMAL") && u.Password == os.Getenv("USER_PASSWORD_NORMAL") {
		u.Role = "user"
		tokenString, err = CreateToken(u.Username, u.Role)
		authorized=true
		if err != nil {
			errorCounter.WithLabelValues("/task/login").Inc()
			log.WithFields(logrus.Fields{
				"task operation": "logging in user",
				"request": "Post /task/login",
				}).Error("error with creating token")
			res.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else if u.Username == os.Getenv("USER_USERNAME_ADMIN") && u.Password == os.Getenv("USER_PASSWORD_ADMIN") {
		u.Role = "admin"
		tokenString, err = CreateToken(u.Username, u.Role)
		authorized=true
		if err != nil {
			errorCounter.WithLabelValues("/task/login").Inc()
			log.WithFields(logrus.Fields{
				"task operation": "logging in user",
				"request": "Post /task/login",
				}).Error("error with creating token")
			res.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		errorCounter.WithLabelValues("/task/login").Inc()
		log.Error("Invalid credentials")
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenResponse := map[string]string{"token": tokenString}

	jsonResponse, err := json.Marshal(tokenResponse)
	if err != nil {
		errorCounter.WithLabelValues("/task/login").Inc()
		log.Error("Error encoding token to JSON:", err)
		log.WithFields(logrus.Fields{
			"task operation": "logging in user",
			"request": "Post /task/login",
			}).Error(err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := res.Write(jsonResponse); err != nil {
		errorCounter.WithLabelValues("/task/login").Inc()
		log.WithFields(logrus.Fields{
			"task operation": "logging in user",
			"request": "Post /task/login",
			}).Error(err.Error())
		res.WriteHeader(http.StatusInternalServerError)
		return
	}
	if authorized {
		res.WriteHeader(http.StatusOK)
		log.WithFields(logrus.Fields{
			"task operation": "logging in user",
			"request": "Post /task/login",
			}).Info(res, tokenString)
		return
	}
	res.WriteHeader(http.StatusUnauthorized)
	log.WithFields(logrus.Fields{
		"task operation": "logging in user",
		"request": "Post /task/login",
		}).Error("Invalid credentials")
}


// GetTaskHandler handles the HTTP request for retrieving a task or all tasks depending on the role of the user.
// It keeps track of the number of requests or errors using Prometheus counters.
// It checks if the user is unauthorized or has an invalid role, then it returns an error response.
// If the request URL contains "getid/{id}" and the role of the user is either "user" or "admin", 
// it retrieves the task with the given {id} and returns it as a JSON response.
// 
// Example request: 
// GET /task/getid/1
// 
// Example response: 
// {
//   "id": 1,
//   "title": "Task 1",
//   "description": "Description of Task 1",
//   "number": 30,
//   "result": 832040,
//   "status": "completed"
// }
// 
// If the user has an "admin" role and the request URL ends with "getAll", it retrieves all tasks and returns them as a JSON response. 
// For pagination, the URL also accepts query parameters "pagesize" and "page" 
// to limit the number of tasks returned per page and the page number to retrieve by "getAll" request.
// 
// Example request: 
// GET /task/getAll?pagesize=10&page=1
// 
// Example response:
//   [
//    {	
//     "id": 1,
//     "title": "Task 1",
//     "description": "Description of Task 1",
//     "number": 30,
//     "result": 0,
//     "status": "in progress"
//   },
//   {
//     "id": 2,
//     "title": "Task 2",
//     "description": "Description of Task 2",
//     "number": 30,
//     "result": 832040,
//     "status": "completed"
//   },
//     ... ]
func GetTaskHandler(res http.ResponseWriter, req *http.Request, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec){
	endPointCounter.WithLabelValues("/task/get").Inc()
	role, err := AuthorizeHandler(res, req)
	if err != nil {
		errorCounter.WithLabelValues("/task/get").Inc()
		http.Error(res, "unauthorized user",http.StatusUnauthorized)
		return
	}
	if role != "user" && role != "admin" {
		errorCounter.WithLabelValues("/task/get").Inc()
		http.Error(res, "unauthorized role", http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": "get a task by id",
			"request": "Post /task/getid/{id}",
			}).Error("unauthorized role")
		return
	}
	parts := strings.Split(req.URL.Path, "/")
	if parts[2] == "getid" {
		taskID, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			errorCounter.WithLabelValues("/task/get").Inc()
			http.Error(res, "Invalid task ID", http.StatusBadRequest)
			log.WithFields(logrus.Fields{
				"task operation": "get task by id",
				"request body": taskID,
				"request": "Get /task/getid/{id}",
				}).Error("Invalid task ID")
				return
			}
			task, err := GetTask(taskID)
			if err != nil {
				errorCounter.WithLabelValues("/task/get").Inc()
				http.Error(res, err.Error(), http.StatusNotFound)
				log.WithFields(logrus.Fields{
					"task operation": "get task by id",
					"request body": taskID,
					"request": "Get /task/getid/{id}",
					}).Error(err.Error())
					return
			}
		taskJSON, _ := json.Marshal(task)
		log.WithFields(logrus.Fields{
		"task operation": "get task by id",
		"request body": string(taskJSON),
		"request": "Get /task/getid/{id}",
		}).Info("Processing request")

		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusFound)
		json.NewEncoder(res).Encode(task)
		return
	} else if parts[len(parts)-1] == "getAll" && role == "admin"{
		pagesize := req.URL.Query().Get("pagesize")
		page := req.URL.Query().Get("page")
		tasks, err := GetAllTasks(pagesize, page)
		if err != nil {
			errorCounter.WithLabelValues("/task/get").Inc()
			http.Error(res, err.Error(), http.StatusInternalServerError)
			log.WithFields(logrus.Fields{
				"task operation": "get all tasks",
				"request": "Get /task/getAll",
			}).Error(err.Error())
			return
		}
		taskJSON, _ := json.Marshal(tasks)
		log.WithFields(logrus.Fields{
			"task operation": "get all tasks",
			"request body": string(taskJSON),
			"request": "Get /task/getAll",
		}).Info("Processing request")
		res.WriteHeader(http.StatusOK)
		json.NewEncoder(res).Encode(tasks)
		return
	} else {
		errorCounter.WithLabelValues("/task/get").Inc()
		http.Error(res, "Unauthorized role", http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": "get all tasks",
			"request": "Get /task/getAll",
			}).Error("Unauthorized role")
		}
}

// GetTask retrieves a task from the database based on the given ID.
// 
// Returns:
// - *models.Task: A pointer to a Task struct containing the task retrieved from the database.
// - error: An error if the SQL query execution fails or the task is not found.
func GetTask(ID int) (*models.Task, error) {
	query := "SELECT * FROM task WHERE id=?"
	row := db.QueryRow(query, ID)
	task := &models.Task{}
	err := row.Scan(&task.Id, &task.Title, &task.Description, &task.Number, &task.Result, &task.Status)
	if err != nil {
        if err == sql.ErrNoRows {
			return nil, fmt.Errorf("task not found for ID %d", ID)
        }
        return nil, fmt.Errorf("failed to scan row into Task struct: %v", err)
    }
	return task, nil
}

// GetAllTasks retrieves all tasks from the "task" table in the database.
// It accepts two query parameters: pagesize and page, which are used for pagination.
// If both pagesize and page are empty, it selects all rows from the table.
// If either pagesize and page are provided, it applies pagination to the query.
// 
// Returns:
// - []models.Task: A slice of Task structs containing the tasks retrieved from the database.
// - error: An error if any error occurs.
func GetAllTasks(pagesize string, page string) ([]models.Task, error) {
	var err error
	var rows *sql.Rows
	if page == "" && pagesize ==""{

		rows, err = db.Query("SELECT * FROM task")
		if err != nil {
			return nil, fmt.Errorf("failed to execute query: %v", err)
		}
		defer rows.Close()
	} else {
		offset, err := strconv.Atoi(page)
        if err != nil {
            return nil, fmt.Errorf("failed to convert page to integer: %v", err)
        }

        limit, err := strconv.Atoi(pagesize)
        if err != nil {
            return nil, fmt.Errorf("failed to convert pagesize to integer: %v", err)
        }
		offset = (offset-1) * limit
		rows, err = db.Query("select * from task LIMIT ? OFFSET ?;", limit, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to execute query: %v", err)
		}
		defer rows.Close()
	}

	var tasks []models.Task

	for rows.Next() {
		var task models.Task
		err := rows.Scan(&task.Id, &task.Title, &task.Description, &task.Number, &task.Result, &task.Status)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row into Task struct: %v for task id %d", err, task.Id)
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

// CreateTaskHandler handles the HTTP request for creating a new task.
// It keeps track of the number of requests or errors using Prometheus counters.
// Only users with "user" role can create a task, otherwise it returns an error response.
// It reads the request body to get the task details and validates the input fields of the task from the request body. 
// It also santizes the inputs against XSS attacks.
// 
// With every task created, the task is sent/enqueued to the buffered channel for executing the task 
// and the result of the task is then updated in the database by the worker.
// This fucntion simulates a concurrent mechanism task execution by creating a worker goroutine for each task. 
// 
// 
// Note that the input validation does not allow empty values for the title, description, and number fields.
// 
// Example request body:
// {
//   "title": "Task 1",
//   "description": "Description of Task 1",
//   "number": 30
//  
// }
// 
// Example response:
// {
//   "id": 1,
//   "title": "Task 1",
//   "description": "Description of Task 1",
//   "number": 30,
//   "result": 0,
//   "status": "created"
// }
// 
func CreateTaskHandler(res http.ResponseWriter, req *http.Request, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec) {
	endPointCounter.WithLabelValues("/task/create").Inc()
	role, err:=AuthorizeHandler(res, req)
	if err != nil {
		errorCounter.WithLabelValues("/task/create").Inc()
		http.Error(res, "unauthorized user",http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": "Create a task",
			"request": "Post /task/create",
		}).Error(err.Error())
		return
	}
	if role != "user" {
		errorCounter.WithLabelValues("/task/create").Inc()
		http.Error(res, "unauthorized user",http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": "Create a task",
			"request": "Post /task/create",
		}).Error("unauthorized user")
		return
	}
	task := models.Task{}
	err = json.NewDecoder(req.Body).Decode(&task)
	if err != nil {
		errorCounter.WithLabelValues("/task/create").Inc()
		http.Error(res, "Invalid request body", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"task operation": "Create a task",
			"request": "Post /task/create",
		}).Error("Invalid request body")
		return
	}
	sanitizeTask(&task)
	err = validate.Struct(task)
	if err != nil {
		errorCounter.WithLabelValues("/task/create").Inc()
		http.Error(res, "Invalid resquest body inputs", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"task operation": "Create a task",
			"request": "Post /task/create",
		}).Error("Invalid resquest body inputs")
		return
	}
	err = CreateTask(&task)
	if err != nil {
		errorCounter.WithLabelValues("/task/create").Inc()
		http.Error(res, "Unsuccessful insert operation", http.StatusInternalServerError)
		log.WithFields(logrus.Fields{
			"task operation": "Create a task",
			"request": "Post /task/create",
		}).Error(err.Error())
		return
	}
	go func(task models.Task) {
		taskChan <- task 
		worker(&task)
		<-taskChan
	}(task)

	taskJSON, _ := json.Marshal(task)
	log.WithFields(logrus.Fields{
		"task operation": "Create new task",
		"request body": string(taskJSON),
		"request": "Post /task/create",
	}).Info("Processing request")
	res.WriteHeader(http.StatusAccepted)
	json.NewEncoder(res).Encode(task)
}

// CreateTask inserts a new task into the database.
// If the task's status is empty, it will be set to "created".	
// 
//  Returns:
// - error: An error if the SQL statement execution fails or other errors.
func CreateTask(task *models.Task) error {
	if task.Status == "" {
		task.Status = "created"
	}
	query := "INSERT INTO task(title, description, number, result, status) VALUES(?, ?, ?, ?, ?)"
	create_lock.Lock()
	_, err := db.Exec(query, task.Title, task.Description, task.Number, task.Result, task.Status)
	if err == nil {
		row := db.QueryRow("SELECT LAST_INSERT_ID()")
		err = row.Scan(&task.Id)
		if err != nil {
			return fmt.Errorf("failed to retrieve the last inserted ID: %v", err)
		}
	}
	create_lock.Unlock()
	return err
}

// UpdateTaskHandler handles the HTTP request for updating a task.
// It keeps track of the number of requests or errors using Prometheus counters.
// Only users with "user" or "admin" role can update a task, otherwise it returns an error response.
// It reads the request body to get the task details and validates the input fields of the task from the request body. 
// It also santizes the inputs against XSS attacks.
//
// A user can only update the fibonnaci number of a task if the task/fibonacci is done being executed in the worker pool.
// When user updates the task number, the task is sent to the worker pool for executing the task and the new number is the new fibonacci number of that task 
// and the result of task is then updated. Due to concurrent mechanism, the task that is in progress cannot be updated until it is done executing and its status is set to "completed".
// 
// Note that the input validation does not allow empty values for the id, title, description, and number fields.
// 
// Example request body:
// {
//   "id": 1,
//   "title": "Task 1 updated",
//   "description": "Description of Task 1 updated",
//   "number": 30,
//   "result": 832040,
//   "status": "completed"
// }
// 
// Example response:
// {
//   "id": 1,
//   "title": "Task 1 updated",
//   "description": "Description of Task 1 updated",
//   "number": 30,	
//   "result": 832040,
//   "status": "completed"
// }
func UpdateTaskHandler(res http.ResponseWriter, req *http.Request, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec) {
	endPointCounter.WithLabelValues("/task/update").Inc()
	var statusTask string
	role, err:=AuthorizeHandler(res, req)
	log := logrus.New()
	task := models.Task{}	
	operationType := "update a task"
	if err != nil {
		errorCounter.WithLabelValues("/task/update").Inc()
		http.Error(res, "unauthorized user",http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": operationType,
			"request": "Post /task/update",
			}).Error("unauthorized user")
		return
	}
	if role != "user" && role != "admin"{
		errorCounter.WithLabelValues("/task/update").Inc()
		http.Error(res, "unauthorized user",http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": operationType,
			"request": "Post /task/update",
			}).Error("unauthorized user")
		return
	}
	err = json.NewDecoder((req.Body)).Decode(&task)
	if err != nil {
		errorCounter.WithLabelValues("/task/update").Inc()
		http.Error(res, "Invalid request body", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"task operation": operationType,
			"request": "Post /task/update",
			}).Error("Invalid request body")
			return
	}
	sanitizeTask(&task)

	err = validate.Struct(task)

	if err != nil {
		errorCounter.WithLabelValues("/task/update").Inc()
		http.Error(res, "Invalid request body", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"task operation": "update a task",
			"request": "Post /task/update",
			}).Error("Invalid request body inputs")
			return
	}
	if task.Id == 0 {
		errorCounter.WithLabelValues("/task/update").Inc()
		http.Error(res, "Invalid task Id", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"task operation": operationType,
			"request": "Post /task/update",
		}).Error("Invalid task Id")
		return
	}
	err = db.QueryRow("SELECT Status FROM task WHERE id=?", task.Id).Scan(&statusTask)
	if err != nil {	
		errorCounter.WithLabelValues("/task/update").Inc()
		http.Error(res, "Task not found", http.StatusNotFound)
		log.WithFields(logrus.Fields{
			"task operation": operationType,
			"request": "Post /task/update",
		}).Error("Task not found")
		return
	}

	if statusTask != "completed" {
		errorCounter.WithLabelValues("/task/update").Inc()
		http.Error(res, "Task cannot be updated until the task is completed", http.StatusForbidden)
		log.WithFields(logrus.Fields{
			"task operation": operationType,
			"request": "Post /task/update",
		}).Error("Task cannot be updated until the task is completed")
		return
	} else {
		go func(task models.Task) {
			taskChan <- task
			worker(&task)
			if err != nil {
				errorCounter.WithLabelValues("/task/update").Inc()
				http.Error(res, err.Error(), http.StatusInternalServerError)
				log.WithFields(logrus.Fields{
					"task operation": operationType,
					"request": "Post /task/update",
				}).Error(err.Error())
			}
			<-taskChan
		}(task) 
	}
	taskJSON, _ := json.Marshal(task)
	log.WithFields(logrus.Fields{
		"task operation": operationType,
		"request body": string(taskJSON),
		"request": "POST /task/update",
	}).Info("Processing request")

	res.WriteHeader(http.StatusOK)
	json.NewEncoder((res)).Encode(task)
}

// UpdateTask updates the details of a task in the database.
// Returns:
// - error: An error if the task is not found or the SQL statement execution fails or other errors.
func UpdateTask(task *models.Task) error {
	query := "UPDATE task SET Title=?, Description=?, Number=?, Result=?, Status=? WHERE id=?"
	_, err := db.Exec(query, task.Title, task.Description, task.Number, &task.Result, task.Status, task.Id)
	if err != nil {
		return fmt.Errorf("failed to execute SQL statement: %w", err)
	}
	return nil
}

// DeleteTaskHandler handles the HTTP request for deleting a task.
// It keeps track of the number of requests or errors using Prometheus counters.
// Only users with "admin" role can delete a task, otherwise it returns an error response.
// It reads the request body to get the task ID and validates the input fields of the task from the request body.
//
// Example request body:
// {
//   "id": 1
// }
//
// Returns:
// {
//   "message": "Successfully Deleted task with id=1"
// }
func DeleteTaskHandler(res http.ResponseWriter, req *http.Request, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec){
	endPointCounter.WithLabelValues("/task/delete").Inc()
	role, err := AuthorizeHandler(res, req)
	if err != nil {
		errorCounter.WithLabelValues("/task/delete").Inc()
		http.Error(res, "unauthorized user",http.StatusUnauthorized)
		return
	}
	if role != "admin" {
		errorCounter.WithLabelValues("/task/delete").Inc()
		http.Error(res, "unauthorized user",http.StatusUnauthorized)
		log.WithFields(logrus.Fields{
			"task operation": "Delete a task",
			"request": "Post /task/update",
		}).Error("unauthorized user")
		return
	}
	var message string
	deleteTaskCommand := commands.DeleteTaskCommand{}
	err = json.NewDecoder(req.Body).Decode(&deleteTaskCommand)
	if err != nil {
		errorCounter.WithLabelValues("/task/delete").Inc()
		http.Error(res, "Invalid request body", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"task operation": "Delete a task",
			"request": "Post /task/delete",
		}).Error("Invalid request body")
		return
	}
	if deleteTaskCommand.Id == 0 {
		errorCounter.WithLabelValues("/task/delete").Inc()
		http.Error(res, "Invalid Task Id", http.StatusBadRequest)
		log.WithFields(logrus.Fields{
			"task operation": "Delete a task",
			"request": "Post /task/delete",
		}).Error("Invalid task Id")
		return
	}

	err = DeleteTask(deleteTaskCommand.Id)
	if err != nil {
		errorCounter.WithLabelValues("/task/delete").Inc()
		http.Error(res, err.Error(), http.StatusInternalServerError)
		log.WithFields(logrus.Fields{
			"task operation": "Delete a task",
			"request": "Post /task/delete",
		}).Error(err.Error())
		return
	}
	message = fmt.Sprintf("Successfully Deleted task with id=%d", deleteTaskCommand.Id)
	response := response.Response{
		Message: message,
	}
	log.WithFields(logrus.Fields{
		"task operation": "delete",
		"request": "POST /task/delete",
	}).Info("Processing request")

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	json.NewEncoder(res).Encode(response)
}

// DeleteTask deletes a task from the database based on the given ID.
// Returns:
// - error: An error if the SQL statement execution fails.
func DeleteTask(Id int) error {
	query := "DELETE FROM task WHERE id=?"
	_, err := db.Exec(query, Id)
	if err != nil {
		return fmt.Errorf("failed to execute SQL statement: %v", err)
	}
	return nil
}