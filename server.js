const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ تم الاتصال بقاعدة بيانات BOMA السحابية بنجاح!'))
    .catch((err) => console.error('❌ خطأ في الاتصال:', err.message));

const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    identity: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    accountNumber: { type: Number, required: true, unique: true },
    balance: { type: Number, default: 50.00 },
    isActive: { type: Boolean, default: false },
    otp: { type: String }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
    catIdx: { type: Number, required: true },
    arName: { type: String, required: true },
    enName: { type: String, required: true },
    price: { type: Number, required: true },
    arDesc: { type: String, required: true },
    enDesc: { type: String, required: true },
    img: { type: String, required: true }
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

async function generateUniqueAccountNumber() {
    const lastUser = await User.findOne().sort({ accountNumber: -1 });
    return lastUser && lastUser.accountNumber ? lastUser.accountNumber + 1 : 1000000001;
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'غير مصرح لك بالوصول!' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'انتهت صلاحية الجلسة.' });
        req.user = user; next();
    });
};

// واجهات المصادقة والمحفظة (كما هي)
app.post('/api/auth/signup', async (req, res) => { /*...محذوف للاختصار الداخلي...*/ });
app.post('/api/auth/verify-otp', async (req, res) => { /*...*/ });
app.post('/api/auth/login', async (req, res) => { /*...*/ });
app.post('/api/wallet/checkout', authenticateToken, async (req, res) => { /*...*/ });
app.post('/api/wallet/transfer', authenticateToken, async (req, res) => { /*...*/ });

// ---------------------------------------------------------
// 🛒 واجهات المنتجات والإدارة (Admin APIs)
// ---------------------------------------------------------

// 1. جلب المنتجات (للعملاء والمدير)
app.get('/api/products', async (req, res) => {
    try { const products = await Product.find(); res.json(products); } 
    catch (error) { res.status(500).json({ message: 'خطأ في جلب المنتجات' }); }
});

// 2. إضافة منتج جديد (للمدير)
app.post('/api/products', async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.status(201).json({ message: 'تم إضافة المنتج بنجاح!', product: newProduct });
    } catch (error) { res.status(500).json({ message: 'خطأ في إضافة المنتج' }); }
});

// 3. مسح منتج (للمدير)
app.delete('/api/products/:id', async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: 'تم مسح المنتج بنجاح!' });
    } catch (error) { res.status(500).json({ message: 'خطأ في مسح المنتج' }); }
});

// 4. الحقن التلقائي المبدئي
app.get('/api/products/seed', async (req, res) => {
    try {
        const count = await Product.countDocuments();
        if (count > 0) return res.json({ message: '✅ المنتجات موجودة بالفعل!' });
        // ... بيانات الحقن كما هي
        res.json({ message: 'تم الرفع!' });
    } catch (error) { res.status(500).json({ message: 'خطأ!' }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => { console.log(`🚀 [BOMA Backend v11.0 - Admin] السيرفر جاهز بصلاحيات الإدارة الكاملة!`); });
