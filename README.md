# Secure Serverless API with JWT Authentication using Lambda Authorizers

## Repository Purpose

This repository contains the source code and setup instructions for implementing a secure serverless API on AWS using API Gateway, Lambda Authorizers, and DynamoDB. The goal is to support knowledge sharing and provide a reusable PoC foundation for building APIs protected by JWT-based authentication. The four main Lambda functions in this repository are:

- `restricted_access_lambda.py` – Handles protected API logic.
- `jwt_create_token.py` – Authenticates users and generates JWT tokens.
- `jwt_auth_token.py` – Verifies tokens as a Lambda Authorizer.
- `create_password.py` – Utility for hashing user passwords.

Additionally, this repository includes a `Dockerfile` to assist in the creation of a Lambda Layer. This method allows packaging Python dependencies in a zip file suitable for use in Lambda. The process is described in detail in the article: [Managing Dependencies in AWS Lambda with Docker-Generated Layers](https://medium.com/devops-dev/managing-dependencies-in-aws-lambda-with-docker-generated-layers-78e8f08010b0).

---

## Overview

This solution leverages AWS native services to construct a stateless, scalable, and secure API framework:

- **API Gateway** for routing and securing endpoints.
- **AWS Lambda** for executing backend and security logic.
- **Amazon DynamoDB** for secure user credential storage.
- **JWT** for stateless authentication.

---

## Architecture

### Components

- **API Gateway (DemoAPI):** REST interface for clients.
- **Lambda Functions:**
  - `jwt_create_token` – Validates credentials and issues JWTs.
  - `jwt_auth_token` – Verifies JWTs for protected routes.
  - `restricted_access_lambda` – Returns business logic results.
- **DynamoDB Table (user_credentials):** Stores bcrypt-hashed user credentials.

### Request Flow Summary

1. Client sends login request to `/auth`.
2. API Gateway forwards to `jwt_create_token`.
3. Function fetches and compares password hash from DynamoDB.
4. If valid, returns signed JWT.
5. Client uses JWT in Authorization header for `/api` requests.
6. API Gateway invokes `jwt_auth_token` (Lambda Authorizer).
7. If token is valid, request proceeds to `restricted_access_lambda`.

---

## Setup Instructions

### 1. Create DynamoDB Table
- Name: `user_credentials`
- Primary key: `user_id` (String)

### 2. Create and Deploy Lambda Functions

#### `restricted_access_lambda.py`
- Returns HTTP 200 + timestamp.

#### `jwt_create_token.py`
- Environment variables:
  - `USER_CREDENTIALS_TABLE_NAME = user_credentials`
  - `JWT_SECRET = <your_secret>`
- Permissions:
  - DynamoDB read access
  - CloudWatch logging

#### `jwt_auth_token.py`
- Environment variable:
  - `JWT_SECRET = <your_secret>`

#### `create_password.py`
- Local utility script to generate bcrypt hashes

### 3. API Gateway Configuration

#### REST API: `DemoAPI`
- **/auth (POST)**
  - Integration: `jwt_create_token`
- **/api (GET)**
  - Integration: `restricted_access_lambda`
  - Authorization: Custom Lambda Authorizer (`jwt_auth_token`)

#### Lambda Authorizer Setup
- Name: `protect_lambda`
- Token source: `Authorization` header
- Attach to `/api` GET method

### 4. Deployment
- Deploy the API to a stage (e.g., `dev`).

---

## Build Lambda Layer

To build a Lambda Layer using Docker (containing external Python dependencies), follow the steps below:

### Step 1: Verify Docker Installation
```bash
docker --version
docker ps
```

### Step 2: Build the Docker Image
```bash
docker build -t lambda_layer .
```

### Step 3: Confirm Image Creation
```bash
docker images
```

### Step 4: Run a Container from the Image
```bash
docker run --name my_lambda_layer_container lambda_layer
```

### Step 5: Export the Lambda Layer Zip File
```bash
docker cp my_lambda_layer_container:/home/python_dependencies.zip .
```

### Step 6: Cleanup (Optional)
Stop and remove the Docker container and image:
```bash
docker stop my_lambda_layer_container
docker rm my_lambda_layer_container
docker rmi lambda_layer
```

The resulting `python_dependencies.zip` file can now be uploaded to AWS Lambda as a Layer.

---

## Testing

### Generate Token
```bash
curl -X POST <invoke_url>/auth -d '{"user_id": "testuser", "password": "password123"}'
```

### Call Secured Endpoint
```bash
curl -H "Authorization: Bearer <jwt_token>" <invoke_url>/api
```

---

## Security Notes
- Use strong secrets for JWT signing.
- Apply strict IAM permissions to Lambda roles.
- Never store plain text passwords.

---

## References
- [API Gateway Lambda Authorizer Documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)
- [Using JWTs for Authorization](https://jwt.io/introduction/)
- [Managing Dependencies in AWS Lambda with Docker-Generated Layers](https://medium.com/devops-dev/managing-dependencies-in-aws-lambda-with-docker-generated-layers-78e8f08010b0)

