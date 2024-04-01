// KonzekWebService is a concurrent web service that provides CRUD operations for tasks.
//
// It implements CRUD operations and uses MySQL database to store tasks in task table.
// The service also provides a login endpoint to authenticate users.
// Rating limit with rate limit of 2 events per second and burst limit of 20 events to protect against abuse is applied.
// This service implements concurrent mechanism that executes every task when created by user.
// It also provides Prometheus metrics for monitoring and recording metrics.
// It is also dockerized and deployed to Google Cloud.
// In tests directory, unit testing is implemented to test the performance of the service's endpoints.
//
// The following endpoints are available:
//
//  1. POST /task/create - Create a new task
//  2. POST /task/update - Update an existing task
//  3. POST /task/delete - Delete an existing task
//  4. GET /task/getid/{id} - Get a task by ID
//  5. GET /task/getAll - Get all tasks
//  6. POST /task/login - Login to the service
//  7. GET /metrics - Display Prometheus metrics
//
// You may use godoc -http=:6060 to view the documentation in your browser.
package main

import (
	"KonzekWebService/handlers"
	"KonzekWebService/response"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)
var (
	limiter = rate.NewLimiter(2, 20)
	errorCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "myapp_errors_total",
        Help: "Total number of errors occurred in the application.",
    }, []string{"endpoint"})
	endPointCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "myapp_endpoint_calls_total",
        Help: "Total number of errors occurred in the application.",
    }, []string{"endpoint"})
	log = logrus.New()

)

// A struct type that represents a handler function with metrics. 
type HandlerFuncWithMetrics func(http.ResponseWriter, *http.Request, *prometheus.CounterVec, *prometheus.CounterVec)

func main() {

	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}
	prometheus.MustRegister(errorCounter)
	prometheus.MustRegister(endPointCounter)
	handlers.Initialize()
	http.HandleFunc("/task/create", MetricsHandler(handlers.CreateTaskHandler, endPointCounter, errorCounter))
	http.HandleFunc("/task/update", MetricsHandler(handlers.UpdateTaskHandler, endPointCounter, errorCounter))
	http.HandleFunc("/task/delete", MetricsHandler(handlers.DeleteTaskHandler, endPointCounter, errorCounter))
	http.HandleFunc("/task/getid/{id}", MetricsHandler(handlers.GetTaskHandler, endPointCounter, errorCounter))
	http.HandleFunc("/task/getAll", MetricsHandler(handlers.GetTaskHandler, endPointCounter, errorCounter))
	http.HandleFunc("/task/login", MetricsHandler(handlers.LoginHandler, endPointCounter, errorCounter))
	
	// Start the server
	http.Handle("/metrics", promhttp.Handler())
	port := os.Getenv("PORT")
	log.Info("Server listening on port " + port)
	http.ListenAndServe(":" + port, nil)
}

// rateLimiter is a middleware function that implements rate limiting for HTTP requests.
// It takes a `next` function as a parameter, which is the handler function to be called if the request is allowed.
// If the request is not allowed due to rate limiting, it returns a JSON response with an error message and HTTP status code 429 (Too Many Requests).
// The `endPointCounter` and `errorCounter` parameters are Prometheus CounterVecs used for monitoring and recording metrics.
func rateLimiter(next func(res http.ResponseWriter, req *http.Request, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec)) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if !limiter.Allow() {
			message := response.Message{
				Status: "Request Failed",
				Body:   "The API is at capacity, try again later.",
			}
			res.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(res).Encode(&message)
			return
		} else {
			next(res, req, endPointCounter, errorCounter)
		}
	})
}

// MetricsHandler is a middleware function that wraps the provided handler function
// with metrics collection and rate limiting capabilities.
// It takes in a handler function, Prometheus counter vectors for endpoint and error metrics,
// and returns an http.HandlerFunc.
func MetricsHandler(handlerFunc HandlerFuncWithMetrics, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		rateLimiterFunc := rateLimiter(func(res http.ResponseWriter, req *http.Request, endPointCounter *prometheus.CounterVec, errorCounter *prometheus.CounterVec) {
			handlerFunc(res, req, endPointCounter, errorCounter)
		})
        rateLimiterFunc.ServeHTTP(res, req)
    }
}