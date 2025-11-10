import express from "express";
import bcrypt from "bcryptjs";
import Jwt from "jsonwebtoken";
import cors from "cors";
import { check, validationResult } from "express-validator";
import dotenv from "dotenv";
dotenv.config();


const app = express();

app.use(express.json());
app.use(cors());

const jwtKey = 'yummtumm';


let users = [];
let products = [
  { id: 1, name: "Pizza", price: 9.99 },
  { id: 2, name: "Burger", price: 6.49 },
  { id: 3, name: "Pasta", price: 8.75 }
];
let orders = [];

const registerValidators = [
  check("name", "Name is required").not().isEmpty(),
  check("email", "Please include a valid email").isEmail(),
  check("password", "Password must be at least 6 characters").isLength({ min: 6 })
];



app.post('/register', registerValidators, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json(errors);
  }

  const { email, password, name } = req.body;

  
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
  }


  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, name, email, password: hashedPassword };
  users.push(newUser);

  Jwt.sign({ email, name }, jwtKey, { expiresIn: '2h' }, (err, token) => {
    if (err) {
      return res.status(500).json({ errors: [{ msg: 'Token generation failed' }] });
    }
    res.status(200).json({ user: { name, email }, auth: token });
  });
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ errors: [{ msg: 'User not found' }] });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
  }

  Jwt.sign({ email, name: user.name }, jwtKey, { expiresIn: '2h' }, (err, token) => {
    if (err) {
      return res.status(500).json({ errors: [{ msg: 'Token generation failed' }] });
    }
    res.status(200).json({ user: { name: user.name, email: user.email }, auth: token });
  });
});


app.post('/getAllData', verifyToken, (req, res) => {
  const { name } = req.body;
  if (!name || name === '') {
    return res.json(products);
  }
  const filtered = products.filter(p => p.name.toLowerCase().includes(name.toLowerCase()));
  res.json(filtered);
});


app.post('/placeOrder', verifyToken, (req, res) => {
  const { email, order_data } = req.body;

  if (!email || !order_data) {
    return res.status(400).json({ errors: [{ msg: 'Invalid order data' }] });
  }

  const existingOrder = orders.find(o => o.email === email);
  if (existingOrder) {
    existingOrder.order_data.push(...order_data);
  } else {
    orders.push({ email, order_data });
  }

  res.json({ message: 'Your order has been placed successfully' });
});


function verifyToken(req, res, next) {
  let token = req.headers['authorization'];
  if (!token) {
    return res.status(403).json({ errors: [{ msg: 'Token missing' }] });
  }
  token = token.split(' ')[1];
  Jwt.verify(token, jwtKey, (err) => {
    if (err) {
      return res.status(403).json({ errors: [{ msg: 'Invalid token' }] });
    }
    next();
  });
}


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
