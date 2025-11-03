# Lab №3: Authentication and Authorization

## Project Background

The current project is a continuation of the development started in the [node-toDo-app-db](https://github.com/acetvertacova/node-toDo-app-db) repository.

---

## 🎯 Objective

- Learn methods of authentication and authorization in backend applications using Node.js.
- Implement REST API protection using JWT (JSON Web Token).
- Learn to restrict access to resources based on user roles.


---

## Installation and Project Launch Instructions

1. Install Node.js

    Make sure you have Node.js installed. Check your version:
   
```
    node -v
    npm -v
```

2. Clone or Download the Project

```
   git clone <repo-url>
   cd <your-project-folder>
```

3. Install Dependencies

```
    npm install
```

4. Run migrations

```
    npx sequelize-cli db:migrate
```

5. Start the server

```
    npm run dev
```

---

## Project's Structure

    node-toDo-app-db/
    ├── config/
    │   └── config.js                    # Database configuration for Sequelize
    ├── middleware/                      # Custom middleware 
    │   └── auth.js                      
    │
    ├── controllers/
    │   ├── CategoriesController.js      # Handles category-related logic
    │   ├── UserController.js            # Handles user-related logic
    │   └── TodoController.js            # Handles todo-related logic
    │
    ├── migrations/
    │   ├── 20251026143524-create-category.js  # Migration for creating 'Category' table
    │   ├── 20251026143744-create-user.js      # Migration for creating 'User' table
    │   └── 20251026143745-create-todo.js      # Migration for creating 'Todo' table
    │
    ├── models/
    │   ├── category.js                  # Sequelize model for Category
    │   ├── user.js                      # Sequelize model for User
    │   ├── todo.js                      # Sequelize model for Todo
    │   └── index.js                     # Model initialization and associations
    │
    ├── routes/
    │   ├── CategoryRoute.js             # Routes for categories
    │   ├── UserRoute.js                 # Routes for users
    │   ├── TodoRoute.js                 # Routes for todos
    │   └── swaggerDocs.js               # Swagger documentation routes
    │
    ├── seeders/
    │   ├── 20251026151718-demo-categories.js  # Seeds demo data for categories
    │   ├── 20251026151812-demo-user.js        # Seeds demo data for users
    │   └── 20251026151800-demo-todos.js       # Seeds demo data for todos
    │
    ├── swagger/
    │   └── swagger.js                   # Swagger configuration for API docs
    │
    ├── .gitignore                       # Git ignore file
    ├── app.js                           # Main entry point of the application
    ├── example.env                      # Example environment configuration
    ├── package.json                     # Project metadata and dependencies
    ├── package-lock.json                # Dependency lock file
    └── README.md                        # Project documentation

---

## Example Usage

---

### Step 1: Database 

<img src="usage/db.png">

Add a new `users` table and establish a relationship with the `todos` table.

### Users Table

| Field       | Type         | Description                        |
|------------ |------------ |---------------------------------- |
| id          | SERIAL (PK) | Unique identifier for the user     |
| username    | VARCHAR(50) | Unique username                    |
| email       | VARCHAR(100)| User email (unique)                |
| password    | TEXT        | Password hash                      |
| role        | VARCHAR(20) | User role (`user`, `admin`)        |
| created_at  | TIMESTAMP   | Registration date                  |
| updated_at  | TIMESTAMP   | Last update date                   |

### Changes in `todos` Table
Add a `user_id` field to link each task to its owner:

| Field    | Type        | Description                                        |
|----------|------------ |----------------------------------------------------|
| user_id  | INTEGER (FK)| Foreign key referencing `users` table (task owner) |

---

### Step 2: Authentication Implementation

Add authentication routes under `/api/auth`

| Method | URL                  | Description                               | Response       |
|--------|---------------------|--------------------------------------------|----------------|
| POST   | /api/auth/register  | Register a new user                        | 201 Created    |
| POST   | /api/auth/login     | User login (receive JWT token)             | 200 OK         |
| GET    | /api/auth/profile   | Get current user info (by token)           | 200 OK         |

---

### Registration (`POST /register`)

```javascript
// register function
export async function register(req, res) {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const existingUser = await User.findOne({
            where: { [Op.or]: [{ email }, { username }] }
        });

        if (existingUser) {
            throw new Error('Username or email already in use');
        }

        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
}
```

### Example: Register

POST /api/auth/register

Content-Type: application/json

{

  "username": "john_doe",

  "email": "john@example.com",
  
  "password": "securePassword123"
  
}

---

### Login (`POST /login`)
1. Check that the user exists and the password is correct.
2. Generate a JWT token containing:
   - `userId`
   - `username`
   - `role`
3. Return the token in the response.

```javascript
// login function
export async function login(req, res) {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });

    if (!user) return res.status(401).send("Credentials are wrong");

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).send("Credentials are wrong");

    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "15m" });
    res.json({ token });
}
```

### Example: Login

POST /api/auth/login

Content-Type: application/json

{

  "username": "john_doe",
  
  "password": "securePassword123"
  
}

---

### Profile (`GET /profile`)

1. Pass the token in the `Authorization` header:  `Authorization: Bearer <token>`
2. If the token is valid, return the user information.
3. If invalid, return status `401 Unauthorized`.

```javascript
// getProfile function
export async function getProfile(req, res) {
    const user = await User.findByPk(req.user.id, { attributes: { exclude: ['password'] } });
    if (!user) return res.status(401).json({ message: "User not found" });
    res.json(user);
}
```

### Example: Get Profile

GET /api/auth/profile

Authorization: Bearer <JWT_TOKEN>

---

### Step 3: Authorization Implementation

### Role-Based Access Control

- **User (`role = user`)**
  - Can create tasks (`POST /api/todos`)
  - Can view tasks (`GET /api/todos`)

- **Admin (`role = admin`)**
  - Full access to all tasks (`CRUD /api/todos`)
  - Manage categories (`CRUD /api/categories`)

---

### Middleware: auth.middleware.js

```javascript
import jwt from 'jsonwebtoken';
import db from '../models/index.js';
const Todo = db.Todo;

const SECRET_KEY = process.env.JWT_SECRET || 'your_secret_key';

// Authenticate JWT
export function authenticateJWT(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.sendStatus(401);

    const token = authHeader.split(" ")[1];
    try {
        const payload = jwt.verify(token, SECRET_KEY);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
    }
}
```

---

```javascript
// Admin-only access
export function isAdmin(req, res, next) {
    if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden: Admins only' });
    next();
}
```

---

```javascript
// Owner or Admin access
export async function isOwnerOrAdmin(req, res, next) {
    const user = req.user;
    const todoId = req.params.id;

    if (!user) return res.status(401).json({ message: 'Unauthorized' });

    const todo = await Todo.findByPk(todoId);
    if (!todo) return res.status(404).json({ message: 'Task not found' });

    if (user.role === 'admin' || todo.user_id === user.id) return next();

    return res.status(403).json({ message: 'Forbidden: Not owner or admin' });
}
```

---

### Example Usage in Routes

```javascript
// Users
todoRouter.get('/', authenticateJWT, todoController.getAll);
todoRouter.post('/', authenticateJWT, todoController.create);

// Owners or Admins
todoRouter.get('/:id', authenticateJWT, isOwnerOrAdmin, todoController.getById);

// Admin only
todoRouter.put('/:id', authenticateJWT, isAdmin, todoController.update);
todoRouter.delete('/:id', authenticateJWT, isAdmin, todoController.remove);
todoRouter.patch('/:id/toggle', authenticateJWT, isAdmin, todoController.toggleCompleted);
```

---

## Step 4: Testing and Demonstration

### 1. Register Users

<img src = "usage/users.png">

### 1. Login Users

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "adminpass"
}
```


## Control Questions?

1. What is a relational database, and what advantages does it provide?

A **relational database** is a collection of data points with pre-defined relationships between them. The relational model organizes data into tables — with each row representing an individual record and each column consisting of attributes that contain values. 

**Advantages:**
- Data integrity
- Security
- Backup and disaster recovery
- Community support

2. What types of relationships exist between tables in relational databases?

- `One-to-One (1:1)`: Each row in table A corresponds to one row in table B.
- `One-to-Many (1:N)`: A single row in table A can relate to multiple rows in table B.
- `Many-to-Many (M:N)`: Rows in table A can relate to multiple rows in table B, and vice versa, usually implemented with a reference table.

3. What is a RESTful API, and what is it used for?

REST API stands for Representational State Transfer API. It is a type of API (Application Programming Interface) that allows communication between different systems over the internet. REST APIs work by sending requests and receiving responses, typically in JSON format, between the client and server.

4. What is an SQL injection, and how can it be prevented?

SQL injection is a code injection technique that might destroy your database. SQL injection usually occurs when you ask a user for input, like their `username/userid`, and instead of a `name/id`, the user gives you an SQL statement that you will **unknowingly** run on your database. 

**Prevention:**
- Use parameterized queries or prepared statements.
- Use ORMs that automatically handle query escaping.
- Validate and sanitize user input.

5. What is the difference between an ORM and raw SQL queries? Advantages and disadvantages:

Using raw SQL Development and Object-Relational Mapping (ORM) are two different approaches to interacting with databases in software development.

*Raw SQL:*

**Pros:**
- Full control over queries
- High performance
- Can optimize complex operations

**Cons:**
- Portability
- Complexity
- Risk of SQL injection if not careful

*ORM (Object-Relational Mapping):*

**Pros:**
- Abstraction
- Productivity
- Type safety
- Code readability

**Cons:**
- Performance overhead
- Limited control
- Complexity

---

## Useful Links

1. [**GitHub repository**] (https://github.com/MSU-Courses/development-server-side-applications/tree/main/07_ORM)
2. [**Sequelize CLI Commands** – guide to migrations, seeders, and more:] (https://sequelize.org/docs/v6/other-topics/migrations/)
3. [**Building Your First REST API with Node JS, Express, and Sequelize**](https://medium.com/@mtalhanasir96/building-your-first-rest-api-with-node-js-express-and-sequelize-b041f9910b8a)
4. [**Server Side Pagination in Node JS With Sequelize ORM and MySQL**] (https://medium.com/swlh/server-side-pagination-in-node-js-with-sequelize-orm-and-mysql-73b0190e91fa)
5. [**Types of Relationship in Database**](https://www.geeksforgeeks.org/dbms/types-of-relationship-in-database/)
6. [**REST API Introduction**] (https://www.geeksforgeeks.org/node-js/rest-api-introduction/)
7. [**SQL Injection**] (https://www.w3schools.com/sql/sql_injection.asp)
8. [**The pros and cons of using raw SQL versus ORM for database development**] (https://medium.com/@ritika.adequate/the-pros-and-cons-of-using-raw-sql-versus-orm-for-database-development-e9edde7ee31e)




