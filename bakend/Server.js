const DATABASE_URL=postgres="postgres://postgres:Lokeshnuli@1612@localhost:6969/Railway_DB";
const JWT_SECRET= "a4a478f363cfdb33038b95626373a70a1bd8aa36fc97b183285da4b81dc3af9c";
const ADMIN_API_KEY= "501543cd6fad8b2f8e10420fb3d36392";
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// require('dotenv').config();

const app = express();
const pool = new Pool({ connectionString: DATABASE_URL });
app.use(express.json());

const cors = require('cors');
app.use(cors());

const SECRET_KEY = JWT_SECRET;

// 🔹 Middleware for authentication
const authenticateUser = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid token' });
  }
};

// 🔹 Middleware for admin authentication
const authenticateAdmin = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== ADMIN_API_KEY) return res.status(403).json({ message: 'Forbidden' });
  next();
};

// 🔹 User Registration
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username, hashedPassword, role || 'user']);
  res.status(201).json({ message: 'User registered' });
});

// 🔹 User Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (user.rows.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

  const validPassword = await bcrypt.compare(password, user.rows[0].password);
  if (!validPassword) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user.rows[0].id, role: user.rows[0].role }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// 🔹 Add Train (Admin Only)
app.post('/trains', authenticateAdmin, async (req, res) => {
  const { name, source, destination, total_seats } = req.body;
  await pool.query(
    'INSERT INTO trains (name, source, destination, available_seats) VALUES ($1, INITCAP($2), INITCAP($3), $4)',
    [name, source, destination, total_seats]
  );
  res.status(201).json({ message: 'Train added' });
});

// 🔹 Get Train List (Case-Sensitive Search)
app.get('/trains', async (req, res) => {
  const { source, destination } = req.query;
  const trains = await pool.query(
    'SELECT * FROM trains WHERE source = INITCAP($1) AND destination = INITCAP($2)',
    [source, destination]
  );
  res.json(trains.rows);
});

// 🔹 Get City Suggestions (Autocomplete for Search Input)
app.get('/cities', async (req, res) => {
  const { query } = req.query;
  if (!query || query.length < 3) return res.json([]);

  try {
    const cities = await pool.query(
      `SELECT DISTINCT INITCAP(source) AS city FROM trains WHERE source ILIKE $1
      UNION 
      SELECT DISTINCT INITCAP(destination) AS city FROM trains WHERE destination ILIKE $1`,
      [`${query}%`]
    );
    res.json(cities.rows.map(city => city.city));
  } catch (error) {
    console.error("City suggestion error:", error);
    res.status(500).json({ message: "Error fetching city suggestions" });
  }
});

// 🔹 Train Booking
app.post('/book', authenticateUser, async (req, res) => {
  const { train_id } = req.body;
  console.log("Booking request for train_id:", train_id);

  try {
    await pool.query('BEGIN');
    const train = await pool.query('SELECT available_seats FROM trains WHERE id = $1 FOR UPDATE', [train_id]);

    if (train.rows.length === 0) throw new Error('Train not found');
    if (train.rows[0].available_seats === 0) throw new Error('No seats available');

    await pool.query('UPDATE trains SET available_seats = available_seats - 1 WHERE id = $1', [train_id]);
    const booking = await pool.query('INSERT INTO bookings (user_id, train_id) VALUES ($1, $2) RETURNING *', [req.user.id, train_id]);
    await pool.query('COMMIT');

    res.status(201).json({ message: 'Seat booked', booking: booking.rows[0] });
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error("Booking error:", error);
    res.status(400).json({ message: error.message });
  }
});

// 🔹 Get Specific Booking Details
// app.get('/booking/:id', authenticateUser, async (req, res) => {
//   const booking = await pool.query('SELECT * FROM bookings WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
//   if (booking.rows.length === 0) return res.status(404).json({ message: 'Booking not found' });
//   res.json(booking.rows[0]);
// });

// 🔹 Get Specific Booking Details with Train Info
app.get('/booking/:id', authenticateUser, async (req, res) => {
  try {
    const bookingQuery = `
      SELECT 
        b.id AS booking_id,
        t.name AS train_name,
        t.source,
        t.destination
      FROM bookings b
      JOIN trains t ON b.train_id = t.id
      WHERE b.id = $1 AND b.user_id = $2
    `;

    const { rows } = await pool.query(bookingQuery, [req.params.id, req.user.id]);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error("Error fetching booking details:", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// 🔹 Test Database Connection
app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW();");
    res.json({ message: "Database connected successfully", timestamp: result.rows[0] });
  } catch (error) {
    console.error("Database connection error:", error);
    res.status(500).json({ error: "Database connection failed" });
  }
});



app.listen(3000, () => console.log('🚀 Server running on port 3000'));


// ee file run chesi chudu post ,an lo