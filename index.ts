const express = require('express');
const bcrypt = require('bcryptjs');
const Joi = require('joi');

const app = express();
const port = 3000;

import { Request, Response } from 'express';
import { json } from 'body-parser';

app.use(json());
app.use(express.urlencoded({ extended: true }));

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(username: string): UserEntry | undefined {
  if (username in MEMORY_DB) {
    return MEMORY_DB[username];
  }
  return undefined;
}

function getUserByEmail(email: string): UserEntry | undefined {
  for (let username in MEMORY_DB) {
    if (MEMORY_DB[username].email === email) {
      return MEMORY_DB[username];
    }
  }
  return undefined;
}

const registrationSchema = Joi.object({
  username: Joi.string().min(3).max(24).required(),
  email: Joi.string().email().required(),
  type: Joi.any().valid('user', 'admin').required(),
  password: Joi.string()
    .min(5)
    .max(24)
    .pattern(
      // ^            begin of string
      // (?=.*[a-z])  lower case
      // (?=.*[A-Z])  upper case letter exists
      // (?=.*[-+_!@#$%^&*.,?])     special character -+_!@#$%^&*.,?
      // .+$          end string
      new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[-+_!@#$%^&*.,?]).+$')
    )
    .required(),
});

// Request body -> UserDto
app.post('/register', async (req: Request, res: Response) => {
  // Validate user object using joi
  // - username (required, min 3, max 24 characters)
  // - email (required, valid email address)
  // - type (required, select dropdown with either 'user' or 'admin')
  // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)

  const { value, error } = registrationSchema.validate(req.body);
  const { username, email, type, password } = value;

  // Check input format
  if (error) {
    return res.status(400).send(error.message);
  }

  // Check if username existed in DB
  if (getUserByUsername(username)) {
    return res.status(400).send('Username has been used');
  }

  // Hash Password for storage
  const salt = await bcrypt.genSalt(10);
  const passwordhash = await bcrypt.hash(password, salt);

  // Save to DB
  MEMORY_DB[username] = {
    email,
    type,
    salt,
    passwordhash,
  };

  // Prepare DTO for return
  const dto: UserDto = {
    username,
    email,
    type,
    password: '',
    // Should not return password hash or salt or original password
  };

  res.status(200).send(dto);
});

const loginSchema = Joi.object({
  username: Joi.string().min(3).max(24).required(),
  password: Joi.string()
    .min(5)
    .max(24)
    .pattern(
      // ^            begin of string
      // (?=.*[a-z])  lower case
      // (?=.*[A-Z])  upper case letter exists
      // (?=.*[-+_!@#$%^&*.,?])     special character -+_!@#$%^&*.,?
      // .+$          end string
      new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[-+_!@#$%^&*.,?]).+$')
    )
    .required(),
});

// Request body -> { username: string, password: string }
app.post('/login', async (req: Request, res: Response) => {
  // Return 200 if username and password match
  // Return 401 else

  const { value, error } = loginSchema.validate(req.body);

  // Check input format
  if (error) {
    return res.status(400).send(error.message);
  }

  const { username, password } = value;

  // Check if username existed in DB
  if (getUserByUsername(username)) {
    // Check if password match
    const valid = await bcrypt.compare(
      password,
      MEMORY_DB[username].passwordhash
    );
    if (valid) {
      return res.status(200).send();
    }
  }

  // For security issue, we will not differentiate invalid username & invalid password
  res.status(401).send('Invalid Username or Password');
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
