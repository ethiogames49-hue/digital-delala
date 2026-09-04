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

// ===== FIND PROJECT ROOT (where main.html resides) =====
function findRoot() {
  let current = __dirname;
  while (true) {
    if (fs.existsSync(path.join(current, 'main.html'))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) break; // reached filesystem root
    current = parent;
  }
  return __dirname; // fallback
}
const ROOT = findRoot();
console.log(`📁 Project root: ${ROOT}`);

// ===== SECURITY & MIDDLEWARE =====
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

app.use(cors());
app.use(express.json());

// ===== STATIC FILES SERVING (safe extensions) =====
const safeExtensions = ['.html', '.htm', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg'];
const isSafeFile = (filePath) => {
  const ext = path.extname(filePath).toLowerCase();
  return safeExtensions.includes(ext);
};

app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  if (req.path.startsWith('/api') || req.path.startsWith('/uploads')) return next();

  const filePath = path.join(ROOT, req.path);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile() && isSafeFile(filePath)) {
    express.static(ROOT)(req, res, next);
  } else {
    next();
  }
});

// Root -> main.html
app.get('/', (req, res) => {
  res.sendFile(path.join(ROOT, 'main.html'));
});

// Admin -> admin.html
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(ROOT, 'admin.html'));
});

// ===== MULTER (memory storage) =====
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    const extOk = allowed.test(path.extname(file.originalname).toLowerCase());
    const mimeOk = allowed.test(file.mimetype);
    cb(null, extOk && mimeOk);
  }
});

// ===== MONGODB =====
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
  image: { type: String }, // Base64 data URI
  description: { type: String },
  isAvailable: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Worker = mongoose.model('Worker', workerSchema);

const transactionSchema = new mongoose.Schema({
  workerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Worker', required: true },
  bossName: { type: String, required: true },
  bossEmail: { type: String, required: true },
  amount: { type: Number, required: true },
  telebirrTransactionId: { type: String, required: true, unique: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  phoneNumber: { type: String },
  createdAt: { type: Date, default: Date.now }
});
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

// ============ PUBLIC ROUTES ============

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

app.get('/api/workers/:id', async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });
    res.json({ success: true, data: worker });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/workers/:id/phone', async (req, res) => {
  try {
    const { telebirrTransactionId, bossName, bossEmail, amount } = req.body;
    if (!telebirrTransactionId || !bossName || !bossEmail || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });
    const existing = await Transaction.findOne({ telebirrTransactionId });
    if (existing) return res.status(400).json({ error: 'Transaction ID already used' });

    const transaction = new Transaction({
      workerId: worker._id,
      bossName,
      bossEmail,
      amount,
      telebirrTransactionId,
      status: 'pending',
      phoneNumber: worker.phone
    });
    await transaction.save();

    // Demo: auto-complete
    transaction.status = 'completed';
    await transaction.save();

    res.json({
      success: true,
      message: 'Payment verified successfully',
      data: { phoneNumber: worker.phone, workerName: worker.name }
    });
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

app.post('/api/admin/workers', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const workerData = { ...req.body };
    if (req.file) {
      const base64 = req.file.buffer.toString('base64');
      workerData.image = `data:${req.file.mimetype};base64,${base64}`;
    }
    if (workerData.isAvailable === 'true') workerData.isAvailable = true;
    else if (workerData.isAvailable === 'false') workerData.isAvailable = false;
    const worker = new Worker(workerData);
    await worker.save();
    res.status(201).json({ success: true, data: worker });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/admin/workers/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });

    const updateData = { ...req.body };
    if (req.file) {
      const base64 = req.file.buffer.toString('base64');
      updateData.image = `data:${req.file.mimetype};base64,${base64}`;
    }
    if (updateData.isAvailable === 'true') updateData.isAvailable = true;
    else if (updateData.isAvailable === 'false') updateData.isAvailable = false;

    Object.assign(worker, updateData);
    await worker.save();
    res.json({ success: true, data: worker });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/admin/workers/:id', authenticateToken, async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });
    await worker.deleteOne();
    res.json({ success: true, message: 'Worker deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/transactions', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate('workerId', 'name profession phone')
      .sort({ createdAt: -1 });
    res.json({ success: true, data: transactions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

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
