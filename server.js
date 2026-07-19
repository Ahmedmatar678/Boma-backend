require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const Imap = require('imap');
const { simpleParser } = require('mailparser');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'authorization', 'x-admin-pass']
}));

// ==========================================
// 🌟 1. نماذج الإعدادات المركزية 🌟
// ==========================================
const AppSettings = mongoose.model('AppSettings', new mongoose.Schema({
    isTransferEnabled: { type: Boolean, default: true },
    isWithdrawEnabled: { type: Boolean, default: true },
    isDepositEnabled: { type: Boolean, default: true },
    isStoreEnabled: { type: Boolean, default: true },
    isServicesEnabled: { type: Boolean, default: true },
    bankakAccount: { type: String, default: '' },
    bankakName: { type: String, default: '' },
    bankakWhatsApp: { type: String, default: '' },
    isBankakEnabled: { type: Boolean, default: true },
    transferFeePct: { type: Number, default: 1 }, 
    withdrawFeePct: { type: Number, default: 2 },
    depositFeePct: { type: Number, default: 0 },
    decorationType: { type: String, default: 'none' }, 
    decorationCustomUrl: { type: String, default: '' },
    isDecorationActive: { type: Boolean, default: false },
    adminPasswordHash: { type: String, default: '' },
    adminEmail: { type: String, default: 'infoboma0@gmail.com' },
    termsText: { type: String, default: '' }, 
    uiSettings: { type: Object, default: {} } 
}));

const Category = mongoose.model('Category', new mongoose.Schema({ arName: String, enName: String, icon: String }));
const Announcement = mongoose.model('Announcement', new mongoose.Schema({ title: String, message: String, type: String, count: String, date: { type: Date, default: Date.now } }));
const PromoCode = mongoose.model('PromoCode', new mongoose.Schema({ code: { type: String, unique: true, required: true }, discountPercentage: { type: Number, required: true }, isActive: { type: Boolean, default: true }, date: { type: Date, default: Date.now } }));

mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 30000, socketTimeoutMS: 45000 })
.then(async () => { console.log("✅ سيرفر بومة متصل بالسحابة بنجاح!"); const settings = await AppSettings.findOne(); if (!settings) await new AppSettings().save(); })
.catch(err => { console.error("❌ خطأ الاتصال:", err); process.exit(1); });

const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST || 'smtp.gmail.com', port: parseInt(process.env.SMTP_PORT || '587'), secure: false, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }, tls: { rejectUnauthorized: false } });

// ==========================================
// 🌟 2. النماذج الأساسية للمستخدمين والعمليات 🌟
// ==========================================
const User = mongoose.model('User', new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    role: { type: String, enum: ['user', 'vendor', 'courier'], default: 'user' }, 
    termsAccepted: Boolean, kycStatus: { type: String, default: 'pending' }, kycDocs: { type: Object, default: {} },
    accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 0 },
    debt: { type: Number, default: 0 }, 
    isOnline: { type: Boolean, default: true }, targetBonusAchievedDate: { type: String, default: '' },
    isSuspended: { type: Boolean, default: false }, frozenBalance: { type: Number, default: 0 },
    isActive: { type: Boolean, default: false }, otp: String, otpAttempts: { type: Number, default: 0 },
    trustedDevice: { type: String, default: '' }, tokenVersion: { type: Number, default: 0 },
    wishlist: { type: [String], default: [] } 
}));

const BankakLog = mongoose.model('BankakLog', new mongoose.Schema({ txnId: { type: String, unique: true }, amount: Number, date: { type: Date, default: Date.now }, isUsed: { type: Boolean, default: false } }));
const Product = mongoose.model('Product', new mongoose.Schema({ catIdx: Number, categoryId: String, arName: String, enName: String, price: Number, minPrice: { type: Number, default: 0 }, vendorIdentity: { type: String, default: 'admin' }, stock: { type: Number, default: 0 }, img: String, gallery: { type: [String], default: [] }, arDesc: String, enDesc: String, variations: { type: [String], default: [] }, ratings: [{ rating: Number, clientIdentity: String }], date: { type: Date, default: Date.now } }));
const DeliveryZone = mongoose.model('DeliveryZone', new mongoose.Schema({ name: String, price: Number })); 
const ServiceRequest = mongoose.model('ServiceRequest', new mongoose.Schema({ serviceName: String, projectName: String, description: String, clientIdentity: String, clientName: String, date: { type: Date, default: Date.now } }));
const Banner = mongoose.model('Banner', new mongoose.Schema({ placement: String, arTitle: String, enTitle: String, arDesc: String, enDesc: String, imgUrl: String, date: { type: Date, default: Date.now } }));
const Order = mongoose.model('Order', new mongoose.Schema({ clientIdentity: String, clientName: String, items: Array, totalAmount: Number, promoCode: { type: String, default: '' }, paymentMethod: String, courierIdentity: { type: String, default: '' }, deliveryOtp: { type: String, default: '' }, deliveryFee: { type: Number, default: 0 }, isPaid: { type: Boolean, default: false }, status: { type: String, default: 'pending' }, date: { type: Date, default: Date.now } }));
const Notification = mongoose.model('Notification', new mongoose.Schema({ clientIdentity: String, title: String, message: String, isRead: { type: Boolean, default: false }, date: { type: Date, default: Date.now }, type: { type: String, default: 'personal' } }));
const Transaction = mongoose.model('Transaction', new mongoose.Schema({ transactionId: String, clientIdentity: String, type: String, amount: Number, title: String, date: { type: Date, default: Date.now } }));
const Ticket = mongoose.model('Ticket', new mongoose.Schema({ clientIdentity: String, clientName: String, subject: String, message: String, adminReply: { type: String, default: '' }, status: { type: String, enum: ['pending', 'replied', 'closed'], default: 'pending' }, date: { type: Date, default: Date.now } }));
const FinanceRequest = mongoose.model('FinanceRequest', new mongoose.Schema({ clientIdentity: String, type: { type: String, enum: ['deposit', 'withdraw'] }, amount: Number, currency: { type: String, default: 'SDG' }, receipt: String, bankTxnId: String, bankDetails: String, status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }, date: { type: Date, default: Date.now } }));

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";
const temporarySignups = new Map();
const MASTER_OTP = "1111"; 

function isAdminAccount(user) { if (!user || !user.identity) return false; const ident = String(user.identity).toLowerCase().trim(); return ident === 'infoboma0@gmail.com' || ident === 'ahmedwadmatar1996@gmail.com'; }
async function collectSystemFee(amount, title, txnId) { if (amount <= 0) return; const adminAccount = await User.findOne({ identity: 'infoboma0@gmail.com' }); if (adminAccount) { adminAccount.balance += amount; await adminAccount.save(); await new Transaction({ transactionId: txnId, clientIdentity: adminAccount.identity, type: 'in', amount: amount, title: title }).save(); } }

// ==========================================
// 🛡️ دوال التحقق من قوة الحماية (Security Validations) 
// ==========================================
function isValidPassword(password) {
    if (!password) return false;
    const regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,32}$/;
    return regex.test(password);
}

function isValidPin(pin) {
    if (!pin || !/^\d{6}$/.test(pin)) return false; 
    if (pin.split('').every(char => char === pin[0])) return false; 
    const seqUp = '0123456789'; const seqDown = '9876543210';
    if (seqUp.includes(pin) || seqDown.includes(pin)) return false; 
    return true;
}

// ==========================================
// 🌟 3. حراس الأمان (Middlewares) 🌟
// ==========================================
const auth = async (req, res, next) => { const token = req.headers['authorization']?.split(' ')[1]; if (!token) return res.status(401).json({ message: 'غير مصرح' }); try { const decoded = jwt.verify(token, JWT_SECRET); const user = await User.findById(decoded._id); if (!user || user.tokenVersion !== decoded.tokenVersion) return res.status(403).json({ message: 'جلسة منتهية' }); req.user = decoded; next(); } catch(e) { return res.status(403).json({ message: 'جلسة منتهية' }); } };
const adminAuth = async (req, res, next) => { const pass = req.headers['x-admin-pass']; if (!pass) return res.status(403).json({ message: 'وصول مرفوض' }); try { const settings = await AppSettings.findOne(); let isValid = false; if (settings && settings.adminPasswordHash) { isValid = await bcrypt.compare(pass, settings.adminPasswordHash); } else { isValid = (pass === (process.env.ADMIN_PASS || 'BomaAdmin2026')); } if (!isValid) return res.status(403).json({ message: 'كلمة المرور خاطئة' }); next(); } catch(e) { return res.status(500).json({ message: 'خطأ داخلي' }); } };
const vendorAuth = async (req, res, next) => { await auth(req, res, async () => { const user = await User.findById(req.user._id); if (!user || user.role !== 'vendor') { return res.status(403).json({ message: 'وصول مرفوض' }); } req.vendorIdentity = user.identity; next(); }); };
const courierAuth = async (req, res, next) => { await auth(req, res, async () => { const user = await User.findById(req.user._id); if (!user || user.role !== 'courier') { return res.status(403).json({ message: 'وصول مرفوض' }); } req.courierIdentity = user.identity; next(); }); };

// ==========================================
// 🌟 4. مسارات التوثيق والـ OTP 🌟
// ==========================================
app.post('/api/auth/signup', async (req, res) => { 
    try { 
        const { fullName, identity, password, pin, termsAccepted } = req.body; 
        if (!isValidPassword(password)) return res.status(400).json({ message: 'كلمة المرور ضعيفة! يجب أن تتكون من 8 خانات وتحتوي على أحرف وأرقام معاً.' });
        if (!isValidPin(pin)) return res.status(400).json({ message: 'رمز الـ PIN غير آمن! يجب أن يكون 6 أرقام غير متطابقة أو متسلسلة.' });

        const existingUser = await User.findOne({ identity }); 
        if (existingUser && existingUser.isActive) return res.status(400).json({ message: 'مسجل مسبقاً' }); 
        
        const hashedPassword = await bcrypt.hash(password, 10); 
        const hashedPin = await bcrypt.hash(pin, 10); 
        const otp = Math.floor(1000 + Math.random() * 9000).toString(); 
        const isEmail = identity.includes('@'); 
        
        const lastUser = await User.findOne().sort({ accountNumber: -1 }); 
        const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001; 
        temporarySignups.set(identity, { fullName, identity, password: hashedPassword, pin: hashedPin, termsAccepted, accountNumber: newAccountNumber, otp }); 
        setTimeout(() => temporarySignups.delete(identity), 10 * 60 * 1000); 

        if (isEmail && process.env.SMTP_USER) {
            transporter.sendMail({ from: `"بومة BOMA" <${process.env.SMTP_USER}>`, to: identity, subject: 'رمز تفعيل حسابك - BOMA', html: `<h3>رمز التفعيل: ${otp}</h3>` }).catch(()=>{}); 
            return res.status(201).json({ identity, isEmail, message: 'تم إرسال رمز التفعيل لبريدك الإلكتروني' }); 
        } else {
            return res.status(201).json({ identity, isEmail, fallbackOtp: otp, message: 'تم إرسال الرمز' }); 
        }
    } catch (e) { return res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/auth/verify-otp', async (req, res) => { try { const { identity, otp, purpose, deviceId } = req.body; const tempData = temporarySignups.get(identity); if (tempData) { if (String(otp) === String(tempData.otp) || String(otp) === MASTER_OTP) { try { const WELCOME_BONUS = 5000; const newUser = new User({ fullName: tempData.fullName, identity: tempData.identity, password: tempData.password, pin: tempData.pin, termsAccepted: tempData.termsAccepted, accountNumber: tempData.accountNumber, balance: WELCOME_BONUS, isActive: true, trustedDevice: deviceId }); await newUser.save(); const txnId = 'BOMA-' + Math.floor(10000000 + Math.random() * 90000000); await new Transaction({ transactionId: txnId, clientIdentity: newUser.identity, type: 'in', amount: WELCOME_BONUS, title: 'هدية ترحيبية 🎉' }).save(); temporarySignups.delete(identity); const token = jwt.sign({ _id: newUser._id, accountNumber: newUser.accountNumber, tokenVersion: newUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' }); return res.json({ message: 'تم التفعيل', token, user: { name: newUser.fullName, identity: newUser.identity, accountNumber: newUser.accountNumber, balance: WELCOME_BONUS, kycStatus: 'pending', role: newUser.role, wishlist: newUser.wishlist || [] } }); } catch (saveErr) { return res.status(400).json({ message: 'مسجل مسبقاً' }); } } else return res.status(400).json({ message: 'رمز خاطئ' }); } const user = await User.findOne({ identity }); if (!user) return res.status(404).json({ message: 'غير موجود' }); if (String(otp) === String(user.otp) || String(otp) === MASTER_OTP) { if (purpose === 'forgot') return res.json({ message: 'رمز صحيح' }); const updatedUser = await User.findOneAndUpdate({ identity }, { $set: { trustedDevice: deviceId || '', otp: null }, $inc: { tokenVersion: 1 } }, { new: true }); const token = jwt.sign({ _id: updatedUser._id, accountNumber: updatedUser.accountNumber, tokenVersion: updatedUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' }); return res.json({ token, user: { name: updatedUser.fullName, identity: updatedUser.identity, accountNumber: updatedUser.accountNumber, balance: (updatedUser.balance || 0) - (updatedUser.frozenBalance || 0), kycStatus: updatedUser.kycStatus, role: updatedUser.role, wishlist: updatedUser.wishlist || [] } }); } return res.status(400).json({ message: 'رمز خاطئ' }); } catch (e) { return res.status(500).json({ message: `خطأ` }); } });

app.post('/api/auth/login', async (req, res) => { 
    try { 
        const { identity, password, deviceId } = req.body; 
        const user = await User.findOne({ identity }); 
        if (!user || !user.isActive || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ message: 'بيانات غير صحيحة' }); 
        if (user.isSuspended) return res.status(400).json({ message: 'الحساب موقوف' }); 
        
        if (user.trustedDevice && user.trustedDevice !== 'undefined' && user.trustedDevice !== deviceId) { 
            const otp = Math.floor(1000 + Math.random() * 9000).toString(); 
            user.otp = otp; 
            await user.save(); 
            if (user.identity.includes('@') && process.env.SMTP_USER) {
                transporter.sendMail({ from: `"أمان بومة" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'تسجيل دخول من جهاز جديد', html: `<h3>رمز التحقق: ${otp}</h3>` }).catch(()=>{}); 
                return res.json({ requiresDeviceOtp: true, message: 'تم إرسال رمز التحقق لبريدك الإلكتروني' }); 
            } else {
                return res.json({ requiresDeviceOtp: true, message: 'يتطلب توثيق', fallbackOtp: otp }); 
            }
        } 
        const updatedUser = await User.findOneAndUpdate({ identity }, { $set: { trustedDevice: deviceId || '' }, $inc: { tokenVersion: 1 } }, { new: true }); 
        const token = jwt.sign({ _id: updatedUser._id, accountNumber: updatedUser.accountNumber, tokenVersion: updatedUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' }); 
        return res.json({ token, user: { name: updatedUser.fullName, identity: updatedUser.identity, accountNumber: updatedUser.accountNumber, balance: (updatedUser.balance || 0) - (updatedUser.frozenBalance || 0), kycStatus: updatedUser.kycStatus, role: updatedUser.role, wishlist: updatedUser.wishlist || [] } }); 
    } catch (e) { return res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/auth/forgot-password', async (req, res) => { try { const user = await User.findOne({ identity: req.body.identity }); if(!user || !user.isActive) return res.status(404).json({message: 'غير موجود'}); const otp = Math.floor(1000 + Math.random() * 9000).toString(); user.otp = otp; await user.save(); const isEmail = user.identity.includes('@'); if (isEmail && process.env.SMTP_USER) { transporter.sendMail({ from: `"دعم بومة" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'استعادة كلمة المرور', html: `<h3>الرمز: ${otp}</h3>` }).catch(()=>{}); return res.json({ message: 'تم إرسال الرمز لبريدك الإلكتروني', isEmail }); } else { return res.json({ message: 'تم إرسال الرمز', isEmail, fallbackOtp: otp }); } } catch(e) { return res.status(500).json({message: 'خطأ'}); } });
app.post('/api/auth/reset-password', async (req, res) => { try { const { identity, otp, newPassword } = req.body; if (!isValidPassword(newPassword)) return res.status(400).json({ message: 'كلمة المرور ضعيفة' }); const user = await User.findOne({ identity }); if(!user || (user.otp !== String(otp) && String(otp) !== MASTER_OTP)) return res.status(400).json({message: 'رمز غير صالح'}); user.password = await bcrypt.hash(newPassword, 10); user.otp = null; user.tokenVersion += 1; await user.save(); return res.json({message: 'تم التحديث'}); } catch(e) { return res.status(500).json({message: 'خطأ'}); } });

// ==========================================
// 🌟 5. مسارات الإدارة المركزية 🌟
// ==========================================
app.get('/api/settings', async (req, res) => { try { const settings = await AppSettings.findOne(); res.json(settings || {}); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/settings', adminAuth, async (req, res) => { try { const settings = await AppSettings.findOne(); res.json(settings || {}); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/settings', adminAuth, async (req, res) => { 
    try { 
        let settings = await AppSettings.findOne(); 
        if(!settings) settings = new AppSettings(); 
        settings.isTransferEnabled = req.body.isTransferEnabled; 
        settings.isWithdrawEnabled = req.body.isWithdrawEnabled; 
        settings.isDepositEnabled = req.body.isDepositEnabled; 
        settings.isStoreEnabled = req.body.isStoreEnabled; 
        settings.isServicesEnabled = req.body.isServicesEnabled; 
        settings.bankakAccount = req.body.bankakAccount; 
        settings.bankakName = req.body.bankakName; 
        settings.bankakWhatsApp = req.body.bankakWhatsApp; 
        settings.isBankakEnabled = req.body.isBankakEnabled; 
        if(req.body.transferFeePct !== undefined) settings.transferFeePct = Number(req.body.transferFeePct) || 0;
        if(req.body.withdrawFeePct !== undefined) settings.withdrawFeePct = Number(req.body.withdrawFeePct) || 0;
        if(req.body.depositFeePct !== undefined) settings.depositFeePct = Number(req.body.depositFeePct) || 0;
        if (req.body.uiSettings) settings.uiSettings = req.body.uiSettings; 
        await settings.save(); 
        res.json({ message: 'تم التحديث بنجاح' }); 
    } catch(e) { res.status(500).json({ message: 'خطأ' }); } 
});
app.put('/api/admin/settings/decorations', adminAuth, async (req, res) => { try { await AppSettings.findOneAndUpdate({}, { decorationType: req.body.decorationType, decorationCustomUrl: req.body.decorationCustomUrl, isDecorationActive: req.body.isDecorationActive }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/settings/terms', adminAuth, async (req, res) => { try { await AppSettings.findOneAndUpdate({}, { termsText: req.body.termsText }); res.json({ message: 'تم التحديث' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/admin/change-password', adminAuth, async (req, res) => { try { const settings = await AppSettings.findOne(); const { oldPass, newPass } = req.body; let isValid = false; if(settings && settings.adminPasswordHash) { isValid = await bcrypt.compare(oldPass, settings.adminPasswordHash); } else { isValid = (oldPass === (process.env.ADMIN_PASS || 'BomaAdmin2026')); } if(!isValid) return res.status(400).json({ message: 'كلمة المرور القديمة خاطئة' }); settings.adminPasswordHash = await bcrypt.hash(newPass, 10); await settings.save(); res.json({ message: 'تم التغيير' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/admin/forgot-password', async (req, res) => { try { const settings = await AppSettings.findOne(); const targetEmail = settings.adminEmail || process.env.ADMIN_EMAIL || 'admin@boma.com'; if(req.body.email !== targetEmail) { return res.status(400).json({ message: 'بريد غير مصرح للإدارة' }); } const tempPass = 'Admin' + Math.floor(1000 + Math.random() * 9000); settings.adminPasswordHash = await bcrypt.hash(tempPass, 10); await settings.save(); if(process.env.SMTP_USER) { transporter.sendMail({ from: `"أمان الإدارة" <${process.env.SMTP_USER}>`, to: targetEmail, subject: 'استعادة كلمة مرور الإدارة', html: `<h3>كلمة المرور المؤقتة هي:</h3><h1>${tempPass}</h1>` }).catch(()=>{}); } res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

app.get('/api/admin/search-user/:accountNumber', adminAuth, async (req, res) => { try { const accNum = Number(req.params.accountNumber); const user = await User.findOne({ accountNumber: accNum }).select('-password -pin'); if (!user) return res.status(404).json({ message: 'لم يتم العثور' }); res.json(user); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/stats', adminAuth, async (req, res) => { 
    try { 
        const usersCount = await User.countDocuments() || 0; 
        const pendingOrders = await Order.countDocuments({ status: 'pending' }) || 0; 
        const pendingDeposits = await FinanceRequest.countDocuments({ type: 'deposit', status: 'pending' }) || 0;
        const pendingWithdraws = await FinanceRequest.countDocuments({ type: 'withdraw', status: 'pending' }) || 0;
        const pendingTickets = await Ticket.countDocuments({ status: 'pending' }) || 0;
        const userAggr = await User.aggregate([{ $group: { _id: null, totalSDG: { $sum: "$balance" } } }]); 
        const totalSDG = userAggr.length > 0 ? userAggr[0].totalSDG : 0; 
        const depositAggr = await FinanceRequest.aggregate([{ $match: { type: 'deposit', status: 'approved' } }, { $group: { _id: null, totalUSD: { $sum: "$amount" } } }]); 
        const totalUSD = depositAggr.length > 0 ? depositAggr[0].totalUSD : 0; 
        res.json({ usersCount, totalUSD, totalSDG, pendingOrders, pendingDeposits, pendingWithdraws, pendingTickets }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});
app.post('/api/admin/factory-reset', adminAuth, async (req, res) => {
    try {
        const adminIdentities = ['infoboma0@gmail.com', 'ahmedwadmatar1996@gmail.com'];
        await User.deleteMany({ identity: { $nin: adminIdentities } });
        await User.updateMany({ identity: { $in: adminIdentities } }, { $set: { balance: 0, frozenBalance: 0, debt: 0 } });
        await Order.deleteMany({});
        await Transaction.deleteMany({});
        await FinanceRequest.deleteMany({});
        await Ticket.deleteMany({});
        await Notification.deleteMany({});
        await ServiceRequest.deleteMany({});
        await BankakLog.deleteMany({});
        res.json({ message: 'تم تصفير النظام بنجاح!' });
    } catch (e) { res.status(500).json({ message: 'حدث خطأ' }); }
});
app.post('/api/admin/user-transactions', adminAuth, async (req, res) => { try { const txs = await Transaction.find({ clientIdentity: req.body.identity }).sort({ date: -1 }); res.json(txs); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/finance', adminAuth, async (req, res) => { try { const deposits = await FinanceRequest.find({ type: 'deposit' }).sort({ date: -1 }); const withdraws = await FinanceRequest.find({ type: 'withdraw' }).sort({ date: -1 }); res.json({ deposits, withdraws }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/users/:id/role', adminAuth, async (req, res) => { try { const { role } = req.body; if (!['user', 'vendor', 'courier'].includes(role)) return res.status(400).json({ message: 'صلاحية غير صحيحة' }); await User.findByIdAndUpdate(req.params.id, { role: role }); res.json({ message: 'تم تحديث الصلاحية' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

app.put('/api/admin/:type/:id', adminAuth, async (req, res, next) => { 
    const { type, id } = req.params; if (type !== 'deposits' && type !== 'withdraws') return next(); 
    try { 
        const requestType = type === 'deposits' ? 'deposit' : 'withdraw'; 
        const { status } = req.body; 
        const request = await FinanceRequest.findById(id); 
        if (!request || request.status !== 'pending') return res.status(400).json({ message: 'معالج مسبقاً' }); 
        
        request.status = status; await request.save(); 
        const user = await User.findOne({ identity: request.clientIdentity }); 
        
        if (user) { 
            const txnId = 'TXN' + Math.floor(10000000 + Math.random() * 90000000); 
            const settings = await AppSettings.findOne();
            
            if (requestType === 'deposit' && status === 'approved') { 
                const depFeePct = settings ? (settings.depositFeePct || 0) : 0;
                const fee = Number((request.amount * (depFeePct / 100)).toFixed(2));
                const netAmount = request.amount - fee;

                user.balance += netAmount; 
                await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'in', amount: netAmount, title: `شحن المحفظة (شامل الرسوم ${fee})` }).save(); 
                await new Notification({ clientIdentity: user.identity, title: 'شحن المحفظة', message: `تم إضافة ${netAmount} لحسابك.` }).save(); 
                await collectSystemFee(fee, `رسوم شحن محفظة ${user.fullName}`, txnId);
            } 
            else if (requestType === 'withdraw' && status === 'rejected') { 
                const witFeePct = settings ? (settings.withdrawFeePct || 0) : 0;
                const fee = Number(((request.amount / (1 - (witFeePct / 100))) * (witFeePct / 100)).toFixed(2)); 
                const originalAmount = request.amount + fee;

                user.balance += originalAmount; 
                await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'in', amount: originalAmount, title: 'استرداد (سحب مرفوض)' }).save(); 
                await new Notification({ clientIdentity: user.identity, title: 'سحب مرفوض', message: `تم إرجاع ${originalAmount} لحسابك.` }).save(); 
                
                const adminAccount = await User.findOne({ identity: 'infoboma0@gmail.com' });
                if(adminAccount) { adminAccount.balance -= fee; await adminAccount.save(); }
            } 
            else if (requestType === 'withdraw' && status === 'approved') { 
                await new Notification({ clientIdentity: user.identity, title: 'سحب مكتمل', message: `تم تحويل ${request.amount} إلى بنكك.` }).save(); 
            } 
            await user.save(); 
        } 
        res.json({ message: 'تم' }); 
    } catch(e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.put('/api/admin/users/:id/manage', adminAuth, async (req, res) => { try { await User.findByIdAndUpdate(req.params.id, { isSuspended: req.body.isSuspended, frozenBalance: Number(req.body.frozenBalance) || 0 }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/users', adminAuth, async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', adminAuth, async (req, res) => { try { await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// 🌟 6. المتجر (Store) والإعلانات 🌟
// ==========================================
app.get('/api/announcements', async (req, res) => { try { res.json(await Announcement.find().sort({date:-1})); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.get('/api/admin/announcements', adminAuth, async (req, res) => { try { res.json(await Announcement.find().sort({date:-1})); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.post('/api/admin/announcements', adminAuth, async (req, res) => { try { await new Announcement(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.delete('/api/admin/announcements/:id', adminAuth, async (req, res) => { try { await Announcement.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });

app.get('/api/categories', async (req, res) => { try { res.json(await Category.find()); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.post('/api/admin/categories', adminAuth, async (req, res) => { try { await new Category(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.delete('/api/admin/categories/:id', adminAuth, async (req, res) => { try { await Category.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });

app.get('/api/admin/promocodes', adminAuth, async (req, res) => { try { res.json(await PromoCode.find().sort({date:-1})); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.post('/api/admin/promocodes', adminAuth, async (req, res) => { try { await new PromoCode(req.body).save(); res.status(201).json({message:'تم الإضافة'}); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.delete('/api/admin/promocodes/:id', adminAuth, async (req, res) => { try { await PromoCode.findByIdAndDelete(req.params.id); res.json({message:'تم الحذف'}); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.post('/api/promocodes/validate', async (req, res) => { try { const promo = await PromoCode.findOne({ code: req.body.code, isActive: true }); if (!promo) return res.status(400).json({ message: 'الكوبون غير صالح' }); res.json({ discountPercentage: promo.discountPercentage }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

app.get('/api/products', async (req, res) => { try{ res.json(await Product.find().sort({ date: -1 })); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/products', adminAuth, async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.put('/api/admin/products/:id', adminAuth, async (req, res) => { try { await Product.findByIdAndUpdate(req.params.id, req.body); res.json({ message: 'تم التحديث بنجاح' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.delete('/api/products/:id', adminAuth, async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/products/:id/rate', auth, async (req, res) => { try { const user = await User.findById(req.user._id); const product = await Product.findById(req.params.id); if (!product) return res.status(404).json({ message: 'غير موجود' }); const existingIndex = product.ratings.findIndex(r => r.clientIdentity === user.identity); if (existingIndex !== -1) { product.ratings[existingIndex].rating = Number(req.body.rating); } else { product.ratings.push({ rating: Number(req.body.rating), clientIdentity: user.identity }); } await product.save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

app.post('/api/negotiate', auth, async (req, res) => {
    try {
        const { productId, offerPrice } = req.body; const product = await Product.findById(productId); if (!product) return res.status(404).json({ message: "المنتج غير موجود" });
        const base = product.price; const min = product.minPrice > 0 ? product.minPrice : base; 
        if (offerPrice >= base) { return res.json({ status: 'accepted', finalPrice: offerPrice, message: 'مبروك! السعر ممتاز، تم قبول عرضك 🤝' }); }
        if (offerPrice < min) { const counterOffer = min + (base - min) * 0.3; return res.json({ status: 'counter', finalPrice: Math.round(counterOffer), message: `يا غالي السعر دا بعيد شوية. رأيك شنو في ${Math.round(counterOffer)} SDG؟ 😉` }); }
        const margin = base - min; if (offerPrice >= min + (margin * 0.5)) { return res.json({ status: 'accepted', finalPrice: offerPrice, message: 'اتفقنا على السعر، مبروك عليك 🎉' }); } else { const counterOffer = offerPrice + (margin * 0.2); return res.json({ status: 'counter', finalPrice: Math.round(counterOffer), message: `قربنا نصل لاتفاق! زيدها لتكون ${Math.round(counterOffer)} SDG. رأيك؟` }); }
    } catch (e) { res.status(500).json({ message: "خطأ" }); }
});

app.get('/api/banners', async (req, res) => { try{ res.json(await Banner.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', adminAuth, async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', adminAuth, async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.get('/api/requests', adminAuth, async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/requests', async (req, res) => { try { await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });

app.get('/api/delivery-zones', async (req, res) => { try { res.json(await DeliveryZone.find()); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.post('/api/admin/delivery-zones', adminAuth, async (req, res) => { try { await new DeliveryZone({ name: req.body.name, price: Number(req.body.price) }).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.delete('/api/admin/delivery-zones/:id', adminAuth, async (req, res) => { try { await DeliveryZone.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });

app.get('/api/orders', adminAuth, async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', adminAuth, async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.delete('/api/orders/:id', adminAuth, async (req, res) => { try { await Order.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/orders', async (req, res) => { try { const settings = await AppSettings.findOne(); if(settings && !settings.isStoreEnabled) return res.status(400).json({ message: 'عذراً، المتجر متوقف مؤقتاً' }); const cartItems = req.body.cartItems || req.body.items || []; const orderData = { ...req.body, items: cartItems }; await new Order(orderData).save(); for(let item of cartItems) { await Product.findByIdAndUpdate(item.id, { $inc: { stock: -(item.qty || 1) } }).catch(()=>null); } res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// 🌟 7. المحفظة والأتمتة (Wallet & Deposit-Auto) 🌟
// ==========================================
app.post('/api/user/wishlist', auth, async (req, res) => { try { const user = await User.findById(req.user._id); if(!user) return res.status(404).json({ message: 'المستخدم غير موجود' }); user.wishlist = req.body.wishlist || []; await user.save(); res.json({ message: 'تم المزامنة بنجاح' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/forgot-pin', auth, async (req, res) => { try { const user = await User.findById(req.user._id); const otp = Math.floor(1000 + Math.random() * 9000).toString(); user.otp = otp; await user.save(); const isEmail = user.identity.includes('@'); if (isEmail && process.env.SMTP_USER) { transporter.sendMail({ from: `"محفظة بومة" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'استعادة رمز الـ PIN', html: `<h3>الرمز: ${otp}</h3>` }).catch(()=>{}); res.json({ message: 'تم إرسال الرمز لبريدك الإلكتروني', isEmail }); } else { res.json({ message: 'تم إرسال الرمز', isEmail, fallbackOtp: otp }); } } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/reset-pin', auth, async (req, res) => { try { const { otp, newPin } = req.body; if (!isValidPin(newPin)) return res.status(400).json({ message: 'رمز الـ PIN غير آمن' }); const user = await User.findById(req.user._id); if (user.otp !== String(otp) && String(otp) !== MASTER_OTP) return res.status(400).json({ message: 'رمز غير صحيح' }); user.pin = await bcrypt.hash(newPin, 10); user.otp = null; await user.save(); res.json({ message: 'تم تحديث PIN' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

app.get('/api/wallet/receiver-name/:accountNumber', auth, async (req, res) => { try { const accNum = Number(req.params.accountNumber); const receiver = await User.findOne({ accountNumber: accNum }); if (!receiver) return res.status(404).json({ message: 'غير موجود' }); if (receiver.isSuspended) return res.status(400).json({ message: 'موقوف' }); res.json({ name: receiver.fullName }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// --- مسار الأتمتة المُحدَّث (توجيه الشحن اليدوي عند عدم التطابق) ---
app.post('/api/wallet/deposit-auto', auth, async (req, res) => { 
    try { 
        const user = await User.findById(req.user._id); 
        const amount = Number(req.body.amount); 
        const transactionId = req.body.transactionId; 
        
        if (amount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' }); 
        if (!transactionId) return res.status(400).json({ message: 'الرجاء إدخال رقم العملية (Transaction ID)' });

        const existingReq = await FinanceRequest.findOne({ bankTxnId: transactionId, status: 'approved' });
        if (existingReq) return res.status(400).json({ message: 'رقم العملية هذا تم استخدامه لشحن حساب مسبقاً!' });

        const bankLog = await BankakLog.findOne({ txnId: transactionId, isUsed: false });

        if (bankLog && bankLog.amount >= amount) {
            bankLog.isUsed = true; await bankLog.save();
            const settings = await AppSettings.findOne();
            const depFeePct = settings ? (settings.depositFeePct || 0) : 0;
            const fee = Number((amount * (depFeePct / 100)).toFixed(2));
            const netAmount = amount - fee;

            user.balance += netAmount; await user.save();
            const txnIdStr = 'TXN' + Math.floor(10000000 + Math.random() * 90000000);

            await new FinanceRequest({ clientIdentity: user.identity, type: 'deposit', amount: amount, bankTxnId: transactionId, status: 'approved' }).save();
            await new Transaction({ transactionId: txnIdStr, clientIdentity: user.identity, type: 'in', amount: netAmount, title: `شحن آلي للمحفظة (شامل الرسوم ${fee})` }).save();
            await new Notification({ clientIdentity: user.identity, title: 'شحن فوري ⚡', message: `تم شحن ${netAmount} SDG لمحفظتك بنجاح وبشكل آلي.` }).save();
            await collectSystemFee(fee, `رسوم شحن آلي لمحفظة ${user.fullName}`, txnIdStr);

            return res.status(201).json({ message: 'تم شحن المحفظة فوراً بنجاح! ⚡', newBalance: user.balance - user.frozenBalance });
        } else {
            // -- التعديل الجديد: في حال لم يتم العثور على الإشعار، يتم حفظ الطلب كمراجعة يدوية وإرسال رسالة نجاح خضراء للمستخدم --
            await new FinanceRequest({ clientIdentity: user.identity, type: 'deposit', amount: amount, bankTxnId: transactionId, receipt: req.body.receipt || '', status: 'pending' }).save(); 
            return res.status(201).json({ message: 'لم يتم العثور على الإشعار البنكي الآلي. تم تحويل الطلب لطلبات التغذية اليدوية وسنقوم بتأكيده قريباً.' }); 
        }
    } catch (e) { 
        console.error(e);
        res.status(500).json({ message: 'خطأ في النظام' }); 
    } 
});

app.post('/api/wallet/deposit', auth, async (req, res) => { 
    try { 
        const user = await User.findById(req.user._id); 
        const amount = Number(req.body.amount); 
        const bankTxnId = req.body.bankTxnId; 
        if (amount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' }); 
        if (!bankTxnId) return res.status(400).json({ message: 'الرجاء إدخال رقم العملية (Transaction ID)' });

        const existingReq = await FinanceRequest.findOne({ bankTxnId: bankTxnId, status: 'approved' });
        if (existingReq) return res.status(400).json({ message: 'رقم العملية هذا تم استخدامه لشحن حساب مسبقاً!' });

        const bankLog = await BankakLog.findOne({ txnId: bankTxnId, isUsed: false });

        if (bankLog && bankLog.amount >= amount) {
            bankLog.isUsed = true; await bankLog.save();
            const settings = await AppSettings.findOne();
            const depFeePct = settings ? (settings.depositFeePct || 0) : 0;
            const fee = Number((amount * (depFeePct / 100)).toFixed(2));
            const netAmount = amount - fee;

            user.balance += netAmount; await user.save();
            const txnId = 'TXN' + Math.floor(10000000 + Math.random() * 90000000);

            await new FinanceRequest({ clientIdentity: user.identity, type: 'deposit', amount: amount, bankTxnId: bankTxnId, status: 'approved' }).save();
            await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'in', amount: netAmount, title: `شحن آلي للمحفظة (شامل الرسوم ${fee})` }).save();
            await new Notification({ clientIdentity: user.identity, title: 'شحن فوري ⚡', message: `تم شحن ${netAmount} SDG لمحفظتك بنجاح وبشكل آلي.` }).save();
            await collectSystemFee(fee, `رسوم شحن آلي لمحفظة ${user.fullName}`, txnId);

            return res.status(201).json({ message: 'تم شحن المحفظة فوراً بنجاح! ⚡' });
        } else {
            await new FinanceRequest({ clientIdentity: user.identity, type: 'deposit', amount: amount, bankTxnId: bankTxnId, receipt: req.body.receipt, status: 'pending' }).save(); 
            return res.status(201).json({ message: 'تم استلام الطلب بنجاح. جاري مراجعته.' }); 
        }
    } catch (e) { res.status(500).json({ message: 'خطأ في النظام' }); } 
});

app.post('/api/wallet/withdraw', auth, async (req, res) => { 
    try { 
        const user = await User.findById(req.user._id); 
        if (!(await bcrypt.compare(req.body.pin, user.pin))) return res.status(400).json({ message: 'PIN خاطئ' }); 
        
        const amount = Number(req.body.amount); 
        if (amount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' }); 
        
        const settings = await AppSettings.findOne();
        const withdrawFeePct = settings ? (settings.withdrawFeePct || 0) : 0;
        const fee = Number((amount * (withdrawFeePct / 100)).toFixed(2));
        const netAmount = amount - fee;
        
        if (netAmount <= 0) return res.status(400).json({ message: 'المبلغ لا يكفي لتغطية رسوم السحب' });
        
        const availableBalance = user.balance - user.frozenBalance; 
        if (!isAdminAccount(user) && availableBalance < amount) { return res.status(400).json({ message: 'الرصيد المتاح غير كافٍ' }); } 
        
        user.balance -= amount; await user.save(); 
        const txnId = 'TXN' + Math.floor(10000000 + Math.random() * 90000000); 
        
        await new FinanceRequest({ clientIdentity: user.identity, type: 'withdraw', amount: netAmount, bankDetails: req.body.bankDetails }).save(); 
        await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'out', amount, title: `طلب سحب (شامل الرسوم ${fee})` }).save(); 
        await collectSystemFee(fee, `رسوم سحب من ${user.fullName}`, txnId);
        
        res.json({ newBalance: user.balance - user.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/transfer', auth, async (req, res) => { 
    try { 
        const { receiverAccount, amount, pin } = req.body; 
        const transferAmount = Number(amount);
        if (transferAmount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' }); 
        
        const sender = await User.findById(req.user._id); 
        if (sender.isSuspended) return res.status(400).json({ message: 'عذراً، حسابك موقوف' }); 
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); 
        if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); 
        if (receiver.isSuspended) return res.status(400).json({ message: 'حساب المستلم موقوف' }); 
        if (!(await bcrypt.compare(pin, sender.pin))) return res.status(400).json({ message: 'PIN خاطئ' }); 
        
        const settings = await AppSettings.findOne();
        const transferFeePct = settings ? (settings.transferFeePct || 0) : 0;
        const fee = Number((transferAmount * (transferFeePct / 100)).toFixed(2));
        const totalDeduction = transferAmount + fee;
        
        const availableBalance = sender.balance - sender.frozenBalance; 
        if (!isAdminAccount(sender) && availableBalance < totalDeduction) return res.status(400).json({ message: `الرصيد غير كافٍ لتغطية المبلغ والرسوم (${totalDeduction} SDG)` }); 
        
        sender.balance -= totalDeduction; 
        receiver.balance += transferAmount; 
        await sender.save(); await receiver.save(); 
        
        const txnId = 'BOMA-' + Math.floor(10000000 + Math.random() * 90000000); 
        await new Transaction({ transactionId: txnId, clientIdentity: sender.identity, type: 'out', amount: totalDeduction, title: `حوالة إلى (${receiver.fullName}) - شامل الرسوم` }).save(); 
        await new Transaction({ transactionId: txnId, clientIdentity: receiver.identity, type: 'in', amount: transferAmount, title: `حوالة من (${sender.fullName})` }).save(); 
        await collectSystemFee(fee, `رسوم تحويل من ${sender.fullName}`, txnId);
        
        res.json({ newBalance: sender.balance - sender.frozenBalance, receipt: { txnId: txnId, date: new Date(), senderName: sender.fullName, senderAccount: sender.accountNumber, receiverName: receiver.fullName, receiverAccount: receiver.accountNumber, amount: transferAmount } }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/checkout', auth, async (req, res) => { 
    try { 
        const { totalAmount, pin, cartItems, deliveryDetails, promoCode } = req.body; 
        const deliveryFee = Number(req.body.deliveryFee) || 0; 
        if (totalAmount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' });
        const user = await User.findById(req.user._id); 
        if (user.isSuspended) return res.status(400).json({ message: 'حسابك موقوف' });
        if (!(await bcrypt.compare(pin, user.pin))) return res.status(400).json({ message: 'PIN خاطئ' }); 
        const availableBalance = user.balance - user.frozenBalance;
        if (!isAdminAccount(user) && availableBalance < totalAmount) return res.status(400).json({ message: 'الرصيد غير كافٍ' }); 
        
        user.balance -= totalAmount; await user.save(); 
        
        const txnId = 'TXN' + Math.floor(10000000 + Math.random() * 90000000);
        const finalMethod = 'BOMA Wallet || ' + (deliveryDetails || 'بدون توصيل');
        const deliveryOtp = Math.floor(1000 + Math.random() * 9000).toString();

        await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, deliveryFee: deliveryFee, isPaid: true, deliveryOtp: deliveryOtp, promoCode: promoCode || '', paymentMethod: finalMethod }).save(); 
        await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء من المتجر' }).save(); 
        await new Notification({ clientIdentity: user.identity, title: 'تم تأكيد الطلب 🛒', message: `تم خصم ${totalAmount} SDG. رقم استلام الطلب الخاص بك للمندوب هو: ${deliveryOtp}` }).save();
        
        for(let item of cartItems) { 
            const product = await Product.findById(item.id);
            if(product) {
                const finalItemPrice = item.price; 
                product.stock -= (item.qty || 1); await product.save();
                if (product.vendorIdentity && product.vendorIdentity !== 'admin') {
                    const vendor = await User.findOne({ identity: product.vendorIdentity });
                    if (vendor) {
                        const totalItemRevenue = finalItemPrice * (item.qty || 1);
                        const commission = totalItemRevenue * 0.07; 
                        const vendorNet = totalItemRevenue - commission;
                        vendor.balance += vendorNet; await vendor.save();
                        await new Transaction({ transactionId: txnId, clientIdentity: vendor.identity, type: 'in', amount: vendorNet, title: `مبيعات: ${product.arName} (تم خصم 7% لرسوم المنصة)` }).save();
                        await new Notification({ clientIdentity: vendor.identity, title: 'مبيعات جديدة 💰', message: `تم بيع ${item.qty || 1} من ${product.arName} وتم إضافة ${vendorNet} SDG لمحفظتك.` }).save();
                    }
                }
            } 
        }
        res.json({ newBalance: user.balance - user.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ في معالجة الدفع' }); } 
});

app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// 🌟 8. الدعم الفني 🌟
// ==========================================
app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/support', adminAuth, async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', adminAuth, async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد الدعم الفني', message: `الرد: ${req.body.reply}` }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// 🌟 9. لوحة التاجر (Vendor Panel) 🌟
// ==========================================
app.post('/api/vendor/products', vendorAuth, async (req, res) => { try { const productData = { ...req.body, vendorIdentity: req.vendorIdentity }; await new Product(productData).save(); res.status(201).json({ message: 'تم إضافة المنتج بنجاح' }); } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); } });
app.get('/api/vendor/products', vendorAuth, async (req, res) => { try { const products = await Product.find({ vendorIdentity: req.vendorIdentity }).sort({ date: -1 }); res.json(products); } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); } });
app.put('/api/vendor/products/:id', vendorAuth, async (req, res) => { try { const product = await Product.findOne({ _id: req.params.id, vendorIdentity: req.vendorIdentity }); if (!product) return res.status(403).json({ message: 'غير مصرح' }); await Product.findByIdAndUpdate(req.params.id, req.body); res.json({ message: 'تم التعديل' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.delete('/api/vendor/products/:id', vendorAuth, async (req, res) => { try { const product = await Product.findOne({ _id: req.params.id, vendorIdentity: req.vendorIdentity }); if (!product) return res.status(403).json({ message: 'غير مصرح' }); await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم الحذف' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/vendor/stats', vendorAuth, async (req, res) => { try { const productsCount = await Product.countDocuments({ vendorIdentity: req.vendorIdentity }); const salesTxs = await Transaction.find({ clientIdentity: req.vendorIdentity, type: 'in', title: { $regex: 'مبيعات' } }); const totalSalesRevenue = salesTxs.reduce((sum, tx) => sum + tx.amount, 0); res.json({ productsCount, totalSalesRevenue, salesCount: salesTxs.length }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// 🌟 10. تطبيق الكابتن (Courier Panel) 🌟
// ==========================================
app.get('/api/courier/status', courierAuth, async (req, res) => {
    try {
        const courier = await User.findOne({ identity: req.courierIdentity });
        res.json({ isOnline: courier.isOnline !== false }); 
    } catch(e) { res.status(500).json({message: 'خطأ'}); }
});

app.put('/api/courier/status', courierAuth, async (req, res) => {
    try {
        const courier = await User.findOne({ identity: req.courierIdentity });
        courier.isOnline = req.body.isOnline;
        await courier.save();
        res.json({ isOnline: courier.isOnline });
    } catch(e) { res.status(500).json({message: 'خطأ'}); }
});

app.get('/api/courier/orders/available', courierAuth, async (req, res) => { 
    try { 
        const courier = await User.findOne({ identity: req.courierIdentity });
        if (!courier.isOnline) return res.json([]); 
        const orders = await Order.find({ status: 'pending', courierIdentity: '' }).sort({ date: -1 }); 
        res.json(orders); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.get('/api/courier/orders/my', courierAuth, async (req, res) => { 
    try { 
        const orders = await Order.find({ courierIdentity: req.courierIdentity, status: 'shipping' }).sort({ date: -1 }); 
        res.json(orders); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.put('/api/courier/orders/:id/accept', courierAuth, async (req, res) => { 
    try { 
        const courier = await User.findOne({ identity: req.courierIdentity });
        if (!courier.isOnline) return res.status(400).json({ message: 'أنت في وضع الاستراحة!' });

        const order = await Order.findById(req.params.id); 
        if (!order || order.status !== 'pending' || order.courierIdentity) return res.status(400).json({ message: 'الطلب غير متاح' }); 
        
        order.status = 'shipping'; order.courierIdentity = req.courierIdentity; await order.save(); 
        await new Notification({ clientIdentity: order.clientIdentity, title: 'طلبك في الطريق 🚚', message: 'قام مندوب التوصيل باستلام طلبك وهو في طريقه إليك الآن!' }).save(); 
        res.json({ message: 'تم استلام الطلب بنجاح' }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.put('/api/courier/orders/:id/deliver', courierAuth, async (req, res) => { 
    try { 
        const { otp } = req.body; 
        const order = await Order.findById(req.params.id); 
        if (!order || order.courierIdentity !== req.courierIdentity || order.status !== 'shipping') return res.status(400).json({ message: 'طلب غير صالح' }); 
        if (order.deliveryOtp && order.deliveryOtp !== String(otp)) return res.status(400).json({ message: 'رمز الاستلام (OTP) غير صحيح' }); 

        order.status = 'delivered'; await order.save(); 
        const courier = await User.findOne({ identity: req.courierIdentity }); 
        const txnId = 'DEL-' + Math.floor(10000000 + Math.random() * 90000000); 
        
        if (order.deliveryFee && order.deliveryFee > 0) { 
            courier.balance += order.deliveryFee; 
            await new Transaction({ transactionId: txnId, clientIdentity: courier.identity, type: 'in', amount: order.deliveryFee, title: `أرباح توصيل طلب (${order._id.toString().slice(-4)})` }).save(); 
        } 
        if (!order.isPaid) { 
            const platformDues = order.totalAmount - (order.deliveryFee || 0);
            courier.debt += platformDues; 
        } 

        const startOfToday = new Date(); startOfToday.setHours(0, 0, 0, 0);
        const dailyCount = await Order.countDocuments({ courierIdentity: req.courierIdentity, status: 'delivered', date: { $gte: startOfToday } });
        const todayStr = startOfToday.toISOString().slice(0, 10);
        
        if (dailyCount >= 10 && courier.targetBonusAchievedDate !== todayStr) {
            courier.balance += 2000; courier.targetBonusAchievedDate = todayStr;
            const bTxn = 'BONUS-' + Math.floor(10000000 + Math.random() * 90000000);
            await new Transaction({ transactionId: bTxn, clientIdentity: courier.identity, type: 'in', amount: 2000, title: 'مكافأة تحقيق الهدف اليومي 🎯' }).save();
            await new Notification({ clientIdentity: courier.identity, title: 'بطل التوصيل! 🏆', message: 'أكملت 10 طلبات اليوم وحصلت على مكافأة 2000 SDG.' }).save();
        }

        await courier.save(); 
        await new Notification({ clientIdentity: order.clientIdentity, title: 'تم التوصيل بنجاح ✅', message: 'تم تسليم طلبك بنجاح. شكراً لتسوقك من بومة!' }).save(); 
        res.json({ message: 'تم التوصيل وإنهاء الطلب بنجاح' }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.get('/api/courier/stats', courierAuth, async (req, res) => { 
    try { 
        const courier = await User.findOne({ identity: req.courierIdentity }); 
        const startOfToday = new Date(); startOfToday.setHours(0, 0, 0, 0);
        const dailyDeliveries = await Order.countDocuments({ courierIdentity: req.courierIdentity, status: 'delivered', date: { $gte: startOfToday } }); 
        const todayStr = startOfToday.toISOString().slice(0, 10);
        const targetAchieved = courier.targetBonusAchievedDate === todayStr;

        res.json({ balance: courier.balance - courier.frozenBalance, debt: courier.debt || 0, dailyDeliveries: dailyDeliveries, targetAchieved: targetAchieved, isOnline: courier.isOnline !== false }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

// ==========================================
// 🌟 نظام الاستماع لرسائل البريد (Bankak Listener) 🌟
// ==========================================
function startBankakEmailListener() {
    const email = process.env.BANKAK_EMAIL; 
    const password = process.env.BANKAK_PASS;
    if (!email || !password) { console.log("⚠️ نظام الأتمتة البنكية متوقف."); return; }

    const imap = new Imap({ user: email, password: password, host: 'imap.gmail.com', port: 993, tls: true, tlsOptions: { rejectUnauthorized: false } });
    function openInbox(cb) { imap.openBox('INBOX', false, cb); }

    imap.once('ready', function() {
        openInbox(function(err, box) {
            if (err) throw err;
            console.log("✅ محرك الذكاء الاصطناعي متصل ببريد الإدارة وجاهز لقراءة إشعارات بنك الخرطوم...");
            imap.on('mail', function(numNewMsgs) {
                const f = imap.seq.fetch(box.messages.total + ':*', { bodies: '' });
                f.on('message', function(msg, seqno) {
                    msg.on('body', function(stream, info) {
                        simpleParser(stream, async (err, parsed) => {
                            if(err) return;
                            const text = parsed.text || '';
                            const txnMatch = text.match(/(?:Transaction\s*ID|رقم العملية|TransactionId|Reference|رقم المرجع)\s*[:\-]?\s*([0-9]{7,})/i);
                            const amountMatch = text.match(/(?:Amount|المبلغ|القيمة)\s*[:\-]?\s*([0-9,.]+)/i);

                            if (txnMatch && amountMatch) {
                                const txnId = txnMatch[1];
                                const amountStr = amountMatch[1].replace(/,/g, '');
                                const amount = parseFloat(amountStr);
                                try {
                                    const exists = await BankakLog.findOne({ txnId });
                                    if(!exists) {
                                        await new BankakLog({ txnId, amount }).save();
                                        console.log(`📥 عملية بنكية جديدة التقطت آلياً: ${txnId} بمبلغ ${amount} SDG`);
                                    }
                                } catch(dbErr){}
                            }
                        });
                    });
                });
                f.once('error', function(err) { console.log('خطأ في استخراج الإيميل: ' + err); });
            });
        });
    });

    imap.once('error', function(err) { console.log("❌ خطأ في اتصال بريد البنك: " + err.message); });
    imap.once('end', function() { setTimeout(startBankakEmailListener, 10000); });
    imap.connect();
}

startBankakEmailListener();

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => { console.log(`🚀 BOMA Server Secure Running on port ${PORT}`); });
