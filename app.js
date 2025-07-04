require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const streamifier = require('streamifier');
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const Podcast = require('./models/Podcast');
const User = require('./models/User');

const app = express();
const PORT = 3000;

// Middlewares
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error(err));

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.redirect('/login');
  }
}

// Routes
app.get('/', async (req, res) => {
  const podcasts = await Podcast.find().populate('userId', 'username').sort({ uploadedAt: -1 });
  const isLoggedIn = !!req.cookies.token;
  let userId = null;
  if (isLoggedIn) {
    try {
      userId = jwt.verify(req.cookies.token, process.env.JWT_SECRET).userId;
    } catch {}
  }
  res.render('index', { podcasts, isLoggedIn, userId });
});

app.get('/signup', (req, res) => res.render('signup'));
app.get('/login', (req, res) => res.render('login'));

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.send("Username already exists");

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.send("User not found");

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.send("Invalid password");

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.post('/upload', requireAuth, upload.single('podcast'), async (req, res) => {
  if (!req.file) return res.send("No file uploaded");

  const stream = cloudinary.uploader.upload_stream({ resource_type: 'auto' }, async (err, result) => {
    if (err) return res.send("Upload error");
    await new Podcast({
      name: req.body.name,
      url: result.secure_url,
      cloudinaryId: result.public_id,
      userId: req.userId
    }).save();
    res.redirect('/');
  });
  streamifier.createReadStream(req.file.buffer).pipe(stream);
});

app.post('/delete/:id', requireAuth, async (req, res) => {
  try {
    const podcast = await Podcast.findById(req.params.id);
    if (!podcast || podcast.userId.toString() !== req.userId) {
      return res.send("Not authorized to delete");
    }

    await cloudinary.uploader.destroy(podcast.cloudinaryId, { resource_type: 'video' });
    await Podcast.findByIdAndDelete(req.params.id);
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.send("Delete error");
  }
});

app.get('/search', async (req, res) => {
  const query = req.query.q || '';

  // Case-insensitive search on podcast name or user username
  const podcasts = await Podcast.find()
    .populate('userId', 'username')
    .then(podcasts => {
      return podcasts.filter(p =>
        p.name.toLowerCase().includes(query.toLowerCase()) ||
        (p.userId?.username && p.userId.username.toLowerCase().includes(query.toLowerCase()))
      );
    });

  const isLoggedIn = !!req.cookies.token;
  let userId = null;
  if (isLoggedIn) {
    try {
      userId = jwt.verify(req.cookies.token, process.env.JWT_SECRET).userId;
    } catch {}
  }

  res.render('index', { podcasts, isLoggedIn, userId });
});


app.listen(PORT, () => console.log(` Server running at http://localhost:${PORT}`));
