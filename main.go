package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
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
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Read the MongoDB URI from environment variables
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Fatal("MONGODB_URI not set in environment variables")
	}

	// Set clientOptions and connect to MongoDB
	clientOptions := options.Client().ApplyURI(mongoURI)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Test MongoDB connection
	if err := testMongoConnection(); err != nil {
		log.Fatalf("MongoDB connection failed: %v", err)
	}
	log.Println("Connected to MongoDB!")

	// Create a new router
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/login", Login).Methods("POST")

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

	collection := client.Database("go-auth").Collection("users")

	// Check if user already exists
	var result User
	err = collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&result)
	if err == nil {
		json.NewEncoder(w).Encode("User already exists")
		return
	}

	// Hash the password
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		json.NewEncoder(w).Encode("Error while hashing password")
		return
	}

	user.Password = hashedPassword

	// Insert user into the database
	_, err = collection.InsertOne(context.TODO(), user)
	if err != nil {
		json.NewEncoder(w).Encode("Error while inserting user into DB")
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

	collection := client.Database("go-auth").Collection("users")

	// Find user in the database
	var result User
	err = collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&result)
	if err != nil {
		json.NewEncoder(w).Encode("User not found")
		return
	}

	// Check if the password matches
	if !CheckPasswordHash(user.Password, result.Password) {
		json.NewEncoder(w).Encode("Invalid password")
		return
	}

	json.NewEncoder(w).Encode("Login successful")
}

// testMongoConnection tests the connection to MongoDB
func testMongoConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Ping(ctx, nil)
	if err != nil {
		return err
	}
	return nil
}
