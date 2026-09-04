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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
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
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static(uploadDir));

// Serve HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'main.html'));
});
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

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
  image: { type: String }, // can be filename or full URL
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

// Create worker (with image or URL)
app.post('/api/admin/workers', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const workerData = { ...req.body };
    // If a file was uploaded, use it
    if (req.file) {
      workerData.image = req.file.filename;
    } else if (req.body.imageUrl && req.body.imageUrl.trim() !== '') {
      // If imageUrl is provided, store it directly (could be any URL)
      workerData.image = req.body.imageUrl.trim();
    }
    // Convert isAvailable string to boolean
    if (workerData.isAvailable === 'true') workerData.isAvailable = true;
    else if (workerData.isAvailable === 'false') workerData.isAvailable = false;

    const worker = new Worker(workerData);
    await worker.save();
    res.status(201).json({ success: true, data: worker });
  } catch (error) {
    // If file was uploaded but save failed, delete the file
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(400).json({ error: error.message });
  }
});

// Update worker (with image or URL)
app.put('/api/admin/workers/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });

    const updateData = { ...req.body };
    // Handle image: file takes priority
    if (req.file) {
      // Remove old image if it was a local file
      if (worker.image && !worker.image.startsWith('http://') && !worker.image.startsWith('https://')) {
        const oldPath = path.join(uploadDir, worker.image);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }
      updateData.image = req.file.filename;
    } else if (req.body.imageUrl && req.body.imageUrl.trim() !== '') {
      // If imageUrl provided, store it (overwrites previous)
      updateData.image = req.body.imageUrl.trim();
      // If previous image was a local file, remove it
      if (worker.image && !worker.image.startsWith('http://') && !worker.image.startsWith('https://')) {
        const oldPath = path.join(uploadDir, worker.image);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }
    } else {
      // If neither file nor URL provided, keep existing image (or remove? we keep)
      // To remove image, user would send empty string – we handle that
      if (req.body.image === '') {
        // remove image
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

    if (updateData.isAvailable === 'true') updateData.isAvailable = true;
    else if (updateData.isAvailable === 'false') updateData.isAvailable = false;

    Object.assign(worker, updateData);
    await worker.save();
    res.json({ success: true, data: worker });
  } catch (error) {
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(400).json({ error: error.message });
  }
});

// Delete worker
app.delete('/api/admin/workers/:id', authenticateToken, async (req, res) => {
  try {
    const worker = await Worker.findById(req.params.id);
    if (!worker) return res.status(404).json({ error: 'Worker not found' });
    // Remove local image if exists
    if (worker.image && !worker.image.startsWith('http://') && !worker.image.startsWith('https://')) {
      const oldPath = path.join(uploadDir, worker.image);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
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
