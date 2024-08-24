package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// User structure to hold user data
type User struct {
	ID       string `json:"id,omitempty" bson:"_id,omitempty"`
	Email    string `json:"email,omitempty" bson:"email,omitempty"`
	Password string `json:"password,omitempty" bson:"password,omitempty"`
}

var client *mongo.Client

func main() {
	// MongoDB connection URI
	mongoURI := "mongodb+srv://anshulagnihotri008:sIn3vjeajQ9oPj4K@cluster0.yjrxe.mongodb.net/?retryWrites=true&w=majority"

	// Set client options and connect to MongoDB
	clientOptions := options.Client().ApplyURI(mongoURI)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Ping MongoDB to ensure a successful connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	log.Println("Connected to MongoDB!")

	// Create a new router
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/checkMongoConnection", CheckMongoConnection).Methods("GET")

	// Start the server
	log.Fatal(http.ListenAndServe(":8000", router))
}

// HashPassword hashes a given password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash checks if the provided password matches the hashed password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// SignUp handler for creating a new user
func SignUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	collection := client.Database("admin").Collection("users")

	// Check if user already exists
	var result User
	err = collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&result)
	if err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash the password
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		http.Error(w, "Error while hashing password", http.StatusInternalServerError)
		return
	}

	user.Password = hashedPassword

	// Insert user into the database
	_, err = collection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, "Error while inserting user into DB", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("User signed up successfully")
}

// Login handler for user login
func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	collection := client.Database("admin").Collection("users")

	// Find user in the database
	var result User
	err = collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&result)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Check if the password matches
	if !CheckPasswordHash(user.Password, result.Password) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode("Login successful")
}

// CheckMongoConnection checks MongoDB connection by retrieving a collection list
func CheckMongoConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Check if the MongoDB connection is still alive
	err := client.Ping(context.TODO(), nil)
	if err != nil {
		http.Error(w, "MongoDB connection error", http.StatusInternalServerError)
		return
	}

	// Return a success message
	json.NewEncoder(w).Encode("MongoDB connection is alive!")
}
