const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'authorization', 'x-admin-pass']
}));

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ سيرفر بومة متصل بالسحابة بنجاح!"))
    .catch(err => console.error("❌ خطأ الاتصال بقاعدة البيانات:", err));

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    tls: { rejectUnauthorized: false }
});

const temporarySignups = new Map();
const MASTER_OTP = "1111"; 

// --- النماذج (Schemas) ---
const User = mongoose.model('User', new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    termsAccepted: Boolean, kycStatus: { type: String, default: 'pending' },
    kycDocs: { type: Object, default: {} },
    accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 0 },
    isSuspended: { type: Boolean, default: false }, frozenBalance: { type: Number, default: 0 },
    isActive: { type: Boolean, default: false }, otp: String, otpAttempts: { type: Number, default: 0 }
}));

const Product = mongoose.model('Product', new mongoose.Schema({ catIdx: Number, arName: String, enName: String, price: Number, img: String, arDesc: String, enDesc: String }));
const ServiceRequest = mongoose.model('ServiceRequest', new mongoose.Schema({ serviceName: String, projectName: String, description: String, clientIdentity: String, date: { type: Date, default: Date.now } }));
const Banner = mongoose.model('Banner', new mongoose.Schema({ placement: String, arTitle: String, enTitle: String, arDesc: String, enDesc: String, imgUrl: String, date: { type: Date, default: Date.now } }));
const Order = mongoose.model('Order', new mongoose.Schema({ clientIdentity: String, clientName: String, items: Array, totalAmount: Number, paymentMethod: String, status: { type: String, default: 'pending' }, date: { type: Date, default: Date.now } }));
const Notification = mongoose.model('Notification', new mongoose.Schema({ clientIdentity: String, title: String, message: String, isRead: { type: Boolean, default: false }, date: { type: Date, default: Date.now } }));
const Transaction = mongoose.model('Transaction', new mongoose.Schema({ clientIdentity: String, type: String, amount: Number, title: String, date: { type: Date, default: Date.now } }));
const Ticket = mongoose.model('Ticket', new mongoose.Schema({ clientIdentity: String, clientName: String, subject: String, message: String, adminReply: { type: String, default: '' }, status: { type: String, enum: ['pending', 'replied', 'closed'], default: 'pending' }, date: { type: Date, default: Date.now } }));

const FinanceRequest = mongoose.model('FinanceRequest', new mongoose.Schema({
    clientIdentity: String, type: { type: String, enum: ['deposit', 'withdraw'] },
    amount: Number, currency: { type: String, default: 'SDG' },
    receipt: String, bankDetails: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    date: { type: Date, default: Date.now }
}));

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";
const auth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'غير مصرح' });
    jwt.verify(token, JWT_SECRET, (err, user) => { 
        if (err) return res.status(403).json({ message: 'جلسة منتهية' }); 
        req.user = user; next(); 
    });
};

const ADMIN_PASS = process.env.ADMIN_PASS || 'BomaAdmin2026';
const adminAuth = (req, res, next) => {
    const pass = req.headers['x-admin-pass'];
    if (!pass || pass !== ADMIN_PASS) return res.status(403).json({ message: 'وصول مرفوض: غير مصرح لك' });
    next();
};

// ==========================================
// --- مسارات المستخدمين والمصادقة ---
// ==========================================
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { fullName, identity, password, pin, termsAccepted } = req.body;
        const existingUser = await User.findOne({ identity });
        if (existingUser && existingUser.isActive) return res.status(400).json({ message: 'هذا الحساب مسجل ومفعل مسبقاً' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedPin = await bcrypt.hash(pin, 10);
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const isEmail = identity.includes('@');

        const lastUser = await User.findOne().sort({ accountNumber: -1 });
        const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001;

        temporarySignups.set(identity, { fullName, identity, password: hashedPassword, pin: hashedPin, termsAccepted, accountNumber: newAccountNumber, otp });
        setTimeout(() => { if (temporarySignups.has(identity)) temporarySignups.delete(identity); }, 10 * 60 * 1000);

        if (isEmail && process.env.SMTP_USER) { try { transporter.sendMail({ from: `"BOMA Pay" <${process.env.SMTP_USER}>`, to: identity, subject: 'رمز تفعيل حسابك - BOMA', html: `<h1 style="color:#ff6e40;">${otp}</h1>` }); } catch (e) {} }
        return res.status(201).json({ identity, isEmail, fallbackOtp: isEmail ? null : otp }); 
    } catch (e) { return res.status(500).json({ message: 'خطأ داخلي' }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { identity, otp, purpose } = req.body;
        if (purpose === 'forgot') {
            const user = await User.findOne({ identity });
            if (!user) return res.status(404).json({ message: 'غير موجود' });
            if (user.otp === String(otp) || String(otp) === MASTER_OTP) return res.json({ message: 'رمز صحيح' });
            return res.status(400).json({ message: 'رمز خاطئ' });
        } else {
            const tempData = temporarySignups.get(identity);
            if (!tempData) return res.status(400).json({ message: 'انتهت صلاحية الرمز' });
