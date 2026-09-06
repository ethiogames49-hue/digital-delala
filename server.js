require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    const isValid = allowed.test(path.extname(file.originalname).toLowerCase()) &&
                    allowed.test(file.mimetype);
    cb(null, isValid);
  }
});

// Security
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static(uploadDir));

// Serve HTML
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'main.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ============ MODELS ============

const workerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  profession: { type: String, required: true },
  experience: { type: Number, required: true },
  location: { type: String, required: true },
  phone: { type: String, required: true, unique: true },
  price: { type: Number, required: true },
  rating: { type: Number, default: 0 },
  image: { type: String },
  description: { type: String },
  isAvailable: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Worker = mongoose.model('Worker', workerSchema);

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
  workerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bossName: { type: String, required: true },
  bossPhone: { type: String, required: true },
  amount: { type: Number, required: true },
  telebirrTransactionId: { type: String, required: true, unique: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  phoneNumber: { type: String }, // worker's phone (unlocked)
  createdAt: { type: Date, default: Date.now }
});

// TTL index to auto-delete pending transactions after 7 days
transactionSchema.index({ createdAt: 1 }, { expireAfterSeconds: 604800, partialFilterExpression: { status: 'pending' } });

const Transaction = mongoose.model('Transaction', transactionSchema);

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Admin = mongoose.model('Admin', adminSchema);

// ============ MIDDLEWARE ============

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

// Helper to parse boolean from string/boolean
const parseBoolean = (val) => {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') return val.toLowerCase() === 'true';
  return false;
};

// ============ PUBLIC ROUTES ============

// Get all workers (public)
app.get('/api/workers', async (req, res) => {
  try {
    const { profession, location, minPrice, maxPrice, search } = req.query;
    let filter = { isAvailable: true };
    if (profession) filter.profession = new RegExp(profession, 'i');
    if (location) filter.location = new RegExp(location, 'i');
    if (search) {
      filter.$or = [
        { name: new RegExp(search, 'i') },
        { profession: new RegExp(search, 'i') },
        { location: new RegExp(search, 'i') }
      ];
    }
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = Number(minPrice);
      if (maxPrice) filter.price.$lte = Number(maxPrice);
    }
    const workers = await Worker.find(filter).sort({ rating: -1 });
    res.json({ success: true, data: workers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single worker (public)
app.get('/api/workers/:id', async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });
    res.json({ success: true, data: worker });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User signup (public)
app.post('/api/users', async (req, res) => {
  try {
    const { name, phone } = req.body;
    if (!name || !phone) {
      return res.status(400).json({ error: 'Name and phone are required' });
    }
    let user = await User.findOne({ phone });
    if (user) {
      user.name = name;
      await user.save();
      return res.json({ success: true, data: { userId: user._id, name: user.name, phone: user.phone } });
    }
    user = new User({ name, phone });
    await user.save();
    res.status(201).json({ success: true, data: { userId: user._id, name: user.name, phone: user.phone } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Unlock phone: creates a pending transaction
app.post('/api/workers/:id/phone', async (req, res) => {
  try {
    const { telebirrTransactionId, userId, amount } = req.body;
    if (!telebirrTransactionId || !userId || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });

    // FIX: Check if worker is available
    if (!worker.isAvailable) {
      return res.status(400).json({ error: 'Worker is not available' });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // FIX: Prevent duplicate payment for same worker by this user (pending or completed)
    const existingTx = await Transaction.findOne({
      userId,
      workerId: req.params.id,
      status: { $in: ['pending', 'completed'] }
    });
    if (existingTx) {
      return res.status(400).json({
        error: 'You already have a pending or completed transaction for this worker.'
      });
    }

    // FIX: Catch duplicate Telebirr ID
    const transaction = new Transaction({
      workerId: worker._id,
      userId: user._id,
      bossName: user.name,
      bossPhone: user.phone,
      amount,
      telebirrTransactionId,
      status: 'pending',
      phoneNumber: worker.phone // stored but not revealed until confirmed
    });

    await transaction.save();

    res.json({
      success: true,
      message: 'Payment recorded. Waiting for admin confirmation.',
      data: { transactionId: transaction._id }
    });
  } catch (error) {
    // Duplicate key error (telebirrTransactionId)
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Transaction ID already used. Please check and try again.' });
    }
    res.status(500).json({ error: error.message });
  }
});

// Get user's transactions (with phone number only if completed)
app.get('/api/users/:userId/transactions', async (req, res) => {
  try {
    const userId = req.params.userId;
    const transactions = await Transaction.find({ userId })
      .populate('workerId', 'name profession')
      .sort({ createdAt: -1 });
    // Mask phone number if not completed
    const data = transactions.map(t => {
      const obj = t.toObject();
      if (t.status !== 'completed') {
        obj.phoneNumber = null;
      }
      return obj;
    });
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ ADMIN ROUTES ============

app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
    const isValid = await bcrypt.compare(password, admin.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: admin._id, email: admin.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ success: true, token, admin: { email: admin.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all pending transactions (admin)
app.get('/api/admin/transactions/pending', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ status: 'pending' })
      .populate('workerId', 'name profession phone')
      .populate('userId', 'name phone')
      .sort({ createdAt: 1 });
    res.json({ success: true, data: transactions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Confirm a pending transaction (admin)
app.put('/api/admin/transactions/:id/confirm', authenticateToken, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) return res.status(404).json({ error: 'Transaction not found' });
    if (transaction.status !== 'pending') {
      return res.status(400).json({ error: 'Transaction already processed' });
    }
    transaction.status = 'completed';
    await transaction.save();
    res.json({ success: true, message: 'Payment confirmed, phone number released.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// NEW: Reject a pending transaction (admin)
app.put('/api/admin/transactions/:id/reject', authenticateToken, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) return res.status(404).json({ error: 'Transaction not found' });
    if (transaction.status !== 'pending') {
      return res.status(400).json({ error: 'Transaction already processed' });
    }
    transaction.status = 'failed';
    await transaction.save();
    res.json({ success: true, message: 'Transaction rejected.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create worker (admin)
app.post('/api/admin/workers', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const workerData = { ...req.body };
    if (req.file) workerData.image = req.file.filename;
    else if (req.body.imageUrl && req.body.imageUrl.trim() !== '') {
      workerData.image = req.body.imageUrl.trim();
    }
    // FIX: Use helper to parse isAvailable
    if (workerData.isAvailable !== undefined) {
      workerData.isAvailable = parseBoolean(workerData.isAvailable);
    }
    const worker = new Worker(workerData);
    await worker.save();
    res.status(201).json({ success: true, data: worker });
  } catch (error) {
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(400).json({ error: error.message });
  }
});

// Update worker (admin)
app.put('/api/admin/workers/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });

    const updateData = { ...req.body };
    // Handle image update
    if (req.file) {
      // Remove old image if exists and not a URL
      if (worker.image && !worker.image.startsWith('http://') && !worker.image.startsWith('https://')) {
        const oldPath = path.join(uploadDir, worker.image);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }
      updateData.image = req.file.filename;
    } else if (req.body.imageUrl && req.body.imageUrl.trim() !== '') {
      updateData.image = req.body.imageUrl.trim();
      // Remove old local file
      if (worker.image && !worker.image.startsWith('http://') && !worker.image.startsWith('https://')) {
        const oldPath = path.join(uploadDir, worker.image);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }
    } else {
      // If image is explicitly set to empty string, remove image
      if (req.body.image === '') {
        if (worker.image && !worker.image.startsWith('http://') && !worker.image.startsWith('https://')) {
          const oldPath = path.join(uploadDir, worker.image);
          if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        updateData.image = null;
      } else {
        // keep existing
        updateData.image = worker.image;
      }
    }

    // FIX: Parse isAvailable
    if (updateData.isAvailable !== undefined) {
      updateData.isAvailable = parseBoolean(updateData.isAvailable);
    }

    Object.assign(worker, updateData);
    await worker.save();
    res.json({ success: true, data: worker });
  } catch (error) {
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(400).json({ error: error.message });
  }
});

// Delete worker (admin)
app.delete('/api/admin/workers/:id', authenticateToken, async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });

    // FIX: Mark related transactions as failed to avoid orphan references
    await Transaction.updateMany({ workerId: worker._id }, { status: 'failed' });

    // Delete image file if local
    if (worker.image && !worker.image.startsWith('http://') && !worker.image.startsWith('https://')) {
      const oldPath = path.join(uploadDir, worker.image);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    await worker.deleteOne();
    res.json({ success: true, message: 'Worker deleted and related transactions marked as failed.' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all transactions (admin)
app.get('/api/admin/transactions', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate('workerId', 'name profession phone')
      .populate('userId', 'name phone')
      .sort({ createdAt: -1 });
    res.json({ success: true, data: transactions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stats (admin)
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    const totalWorkers = await Worker.countDocuments();
    const availableWorkers = await Worker.countDocuments({ isAvailable: true });
    const totalTransactions = await Transaction.countDocuments();
    const totalRevenue = await Transaction.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    res.json({
      success: true,
      data: {
        totalWorkers,
        availableWorkers,
        totalTransactions,
        totalRevenue: totalRevenue[0]?.total || 0
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ INITIALIZE ADMIN ============

const initializeAdmin = async () => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@digitaldelala.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123456';
    const existing = await Admin.findOne({ email: adminEmail });
    if (!existing) {
      const hashed = await bcrypt.hash(adminPassword, 10);
      const admin = new Admin({ email: adminEmail, password: hashed });
      await admin.save();
      console.log('✅ Admin created');
      console.log(`📧 Email: ${adminEmail}`);
      console.log(`🔑 Password: ${adminPassword}`);
    }
  } catch (error) {
    console.error('Error creating admin:', error);
  }
};

// ============ START SERVER ============

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  await initializeAdmin();
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});
