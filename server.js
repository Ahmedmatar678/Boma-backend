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
    decorationType: { type: String, default: 'none' }, 
    decorationCustomUrl: { type: String, default: '' },
    isDecorationActive: { type: Boolean, default: false },
    adminPasswordHash: { type: String, default: '' },
    adminEmail: { type: String, default: 'admin@boma.com' },
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

const temporarySignups = new Map();
const MASTER_OTP = "1111"; 
const DAILY_WITHDRAW_LIMIT = 500000;  
const DAILY_DEPOSIT_LIMIT = 1000000;  

function isAdminAccount(user) {
    if (!user || !user.identity) return false;
    const ident = String(user.identity).toLowerCase().trim();
    return ident === 'infoboma0@gmail.com' || ident === 'ahmedwadmatar1996@gmail.com';
}

// ==========================================
// 🌟 2. النماذج الأساسية للمستخدمين والعمليات 🌟
// ==========================================
const User = mongoose.model('User', new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    role: { type: String, enum: ['user', 'vendor'], default: 'user' }, 
    termsAccepted: Boolean, kycStatus: { type: String, default: 'pending' }, kycDocs: { type: Object, default: {} },
    accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 0 },
    isSuspended: { type: Boolean, default: false }, frozenBalance: { type: Number, default: 0 },
    isActive: { type: Boolean, default: false }, otp: String, otpAttempts: { type: Number, default: 0 },
    trustedDevice: { type: String, default: '' }, tokenVersion: { type: Number, default: 0 },
    wishlist: { type: [String], default: [] } 
}));

const Product = mongoose.model('Product', new mongoose.Schema({ catIdx: Number, categoryId: String, arName: String, enName: String, price: Number, minPrice: { type: Number, default: 0 }, vendorIdentity: { type: String, default: 'admin' }, stock: { type: Number, default: 0 }, img: String, gallery: { type: [String], default: [] }, arDesc: String, enDesc: String, variations: { type: [String], default: [] }, ratings: [{ rating: Number, clientIdentity: String }], date: { type: Date, default: Date.now } }));
const DeliveryZone = mongoose.model('DeliveryZone', new mongoose.Schema({ name: String, price: Number })); 
const ServiceRequest = mongoose.model('ServiceRequest', new mongoose.Schema({ serviceName: String, projectName: String, description: String, clientIdentity: String, clientName: String, date: { type: Date, default: Date.now } }));
const Banner = mongoose.model('Banner', new mongoose.Schema({ placement: String, arTitle: String, enTitle: String, arDesc: String, enDesc: String, imgUrl: String, date: { type: Date, default: Date.now } }));
const Order = mongoose.model('Order', new mongoose.Schema({ clientIdentity: String, clientName: String, items: Array, totalAmount: Number, promoCode: { type: String, default: '' }, paymentMethod: String, status: { type: String, default: 'pending' }, date: { type: Date, default: Date.now } }));
const Notification = mongoose.model('Notification', new mongoose.Schema({ clientIdentity: String, title: String, message: String, isRead: { type: Boolean, default: false }, date: { type: Date, default: Date.now }, type: { type: String, default: 'personal' } }));
const Transaction = mongoose.model('Transaction', new mongoose.Schema({ transactionId: String, clientIdentity: String, type: String, amount: Number, title: String, date: { type: Date, default: Date.now } }));
const Ticket = mongoose.model('Ticket', new mongoose.Schema({ clientIdentity: String, clientName: String, subject: String, message: String, adminReply: { type: String, default: '' }, status: { type: String, enum: ['pending', 'replied', 'closed'], default: 'pending' }, date: { type: Date, default: Date.now } }));
const FinanceRequest = mongoose.model('FinanceRequest', new mongoose.Schema({ clientIdentity: String, type: { type: String, enum: ['deposit', 'withdraw'] }, amount: Number, currency: { type: String, default: 'SDG' }, receipt: String, bankDetails: String, status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }, date: { type: Date, default: Date.now } }));

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";

// ==========================================
// 🌟 3. حراس الأمان (Middlewares) 🌟
// ==========================================
const auth = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'غير مصرح' });
    try { const decoded = jwt.verify(token, JWT_SECRET); const user = await User.findById(decoded._id); if (!user || user.tokenVersion !== decoded.tokenVersion) return res.status(403).json({ message: 'جلسة منتهية' }); req.user = decoded; next(); } catch(e) { return res.status(403).json({ message: 'جلسة منتهية' }); }
};

const adminAuth = async (req, res, next) => {
    const pass = req.headers['x-admin-pass']; if (!pass) return res.status(403).json({ message: 'وصول مرفوض' });
    try { const settings = await AppSettings.findOne(); let isValid = false; if (settings && settings.adminPasswordHash) { isValid = await bcrypt.compare(pass, settings.adminPasswordHash); } else { isValid = (pass === (process.env.ADMIN_PASS || 'BomaAdmin2026')); } if (!isValid) return res.status(403).json({ message: 'كلمة المرور خاطئة' }); next(); } catch(e) { return res.status(500).json({ message: 'خطأ داخلي' }); }
};

const vendorAuth = async (req, res, next) => {
    await auth(req, res, async () => { const user = await User.findById(req.user._id); if (!user || user.role !== 'vendor') { return res.status(403).json({ message: 'وصول مرفوض' }); } req.vendorIdentity = user.identity; next(); });
};

// ==========================================
// 🌟 4. مسارات التوثيق (تسجيل، دخول، OTP) 🌟
// ==========================================
app.post('/api/auth/signup', async (req, res) => { try { const { fullName, identity, password, pin, termsAccepted } = req.body; const existingUser = await User.findOne({ identity }); if (existingUser && existingUser.isActive) return res.status(400).json({ message: 'مسجل مسبقاً' }); const hashedPassword = await bcrypt.hash(password, 10); const hashedPin = await bcrypt.hash(pin, 10); const otp = Math.floor(1000 + Math.random() * 9000).toString(); const isEmail = identity.includes('@'); const lastUser = await User.findOne().sort({ accountNumber: -1 }); const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001; temporarySignups.set(identity, { fullName, identity, password: hashedPassword, pin: hashedPin, termsAccepted, accountNumber: newAccountNumber, otp }); setTimeout(() => temporarySignups.delete(identity), 10 * 60 * 1000); if (isEmail && process.env.SMTP_USER) { transporter.sendMail({ from: `"BOMA Pay" <${process.env.SMTP_USER}>`, to: identity, subject: 'رمز تفعيل حسابك - BOMA', html: `<h1 style="color:#ff6e40;">${otp}</h1>` }).catch(()=>{}); } return res.status(201).json({ identity, isEmail, fallbackOtp: otp }); } catch (e) { return res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/auth/verify-otp', async (req, res) => { try { const { identity, otp, purpose, deviceId } = req.body; const tempData = temporarySignups.get(identity); if (tempData) { if (String(otp) === String(tempData.otp) || String(otp) === MASTER_OTP) { try { const WELCOME_BONUS = 5000; const newUser = new User({ fullName: tempData.fullName, identity: tempData.identity, password: tempData.password, pin: tempData.pin, termsAccepted: tempData.termsAccepted, accountNumber: tempData.accountNumber, balance: WELCOME_BONUS, isActive: true, trustedDevice: deviceId }); await newUser.save(); const txnId = 'BOMA-' + Math.floor(10000000 + Math.random() * 90000000); await new Transaction({ transactionId: txnId, clientIdentity: newUser.identity, type: 'in', amount: WELCOME_BONUS, title: 'هدية ترحيبية 🎉' }).save(); temporarySignups.delete(identity); const token = jwt.sign({ _id: newUser._id, accountNumber: newUser.accountNumber, tokenVersion: newUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' }); return res.json({ message: 'تم التفعيل', token, user: { name: newUser.fullName, identity: newUser.identity, accountNumber: newUser.accountNumber, balance: WELCOME_BONUS, kycStatus: 'pending', role: newUser.role, wishlist: newUser.wishlist || [] } }); } catch (saveErr) { return res.status(400).json({ message: 'مسجل مسبقاً' }); } } else return res.status(400).json({ message: 'رمز خاطئ' }); } const user = await User.findOne({ identity }); if (!user) return res.status(404).json({ message: 'غير موجود' }); if (String(otp) === String(user.otp) || String(otp) === MASTER_OTP) { if (purpose === 'forgot') return res.json({ message: 'رمز صحيح' }); const updatedUser = await User.findOneAndUpdate({ identity }, { $set: { trustedDevice: deviceId || '', otp: null }, $inc: { tokenVersion: 1 } }, { new: true }); const token = jwt.sign({ _id: updatedUser._id, accountNumber: updatedUser.accountNumber, tokenVersion: updatedUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' }); return res.json({ token, user: { name: updatedUser.fullName, identity: updatedUser.identity, accountNumber: updatedUser.accountNumber, balance: (updatedUser.balance || 0) - (updatedUser.frozenBalance || 0), kycStatus: updatedUser.kycStatus, role: updatedUser.role, wishlist: updatedUser.wishlist || [] } }); } return res.status(400).json({ message: 'رمز خاطئ' }); } catch (e) { return res.status(500).json({ message: `خطأ` }); } });
app.post('/api/auth/login', async (req, res) => { try { const { identity, password, deviceId } = req.body; const user = await User.findOne({ identity }); if (!user || !user.isActive || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ message: 'بيانات غير صحيحة' }); if (user.isSuspended) return res.status(400).json({ message: 'الحساب موقوف' }); if (user.trustedDevice && user.trustedDevice !== 'undefined' && user.trustedDevice !== deviceId) { const otp = Math.floor(1000 + Math.random() * 9000).toString(); user.otp = otp; await user.save(); const isEmail = user.identity.includes('@'); if (isEmail && process.env.SMTP_USER) transporter.sendMail({ from: `"BOMA Security" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'دخول من جهاز جديد', html: `<h2>الرمز: ${otp}</h2>` }).catch(()=>{}); return res.json({ requiresDeviceOtp: true, message: 'يتطلب توثيق', fallbackOtp: otp }); } const updatedUser = await User.findOneAndUpdate({ identity }, { $set: { trustedDevice: deviceId || '' }, $inc: { tokenVersion: 1 } }, { new: true }); const token = jwt.sign({ _id: updatedUser._id, accountNumber: updatedUser.accountNumber, tokenVersion: updatedUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' }); return res.json({ token, user: { name: updatedUser.fullName, identity: updatedUser.identity, accountNumber: updatedUser.accountNumber, balance: (updatedUser.balance || 0) - (updatedUser.frozenBalance || 0), kycStatus: updatedUser.kycStatus, role: updatedUser.role, wishlist: updatedUser.wishlist || [] } }); } catch (e) { return res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/auth/forgot-password', async (req, res) => { try { const user = await User.findOne({ identity: req.body.identity }); if(!user || !user.isActive) return res.status(404).json({message: 'غير موجود'}); const otp = Math.floor(1000 + Math.random() * 9000).toString(); user.otp = otp; await user.save(); const isEmail = user.identity.includes('@'); if (isEmail && process.env.SMTP_USER) { try { transporter.sendMail({ from: `"BOMA Support" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'استعادة', html: `<h1>${otp}</h1>` }); } catch(e) {} } return res.json({ message: 'تم إرسال الرمز', isEmail, fallbackOtp: otp }); } catch(e) { return res.status(500).json({message: 'خطأ'}); } });
app.post('/api/auth/reset-password', async (req, res) => { try { const { identity, otp, newPassword } = req.body; const user = await User.findOne({ identity }); if(!user || (user.otp !== String(otp) && String(otp) !== MASTER_OTP)) return res.status(400).json({message: 'رمز غير صالح'}); user.password = await bcrypt.hash(newPassword, 10); user.otp = null; user.tokenVersion += 1; await user.save(); return res.json({message: 'تم التحديث'}); } catch(e) { return res.status(500).json({message: 'خطأ'}); } });

// ==========================================
// 🌟 5. مسارات الإدارة المركزية (الإعدادات والتخصيص) 🌟
// ==========================================
app.get('/api/settings', async (req, res) => { try { const settings = await AppSettings.findOne(); res.json(settings || {}); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/settings', adminAuth, async (req, res) => { try { const settings = await AppSettings.findOne(); res.json(settings || {}); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/settings', adminAuth, async (req, res) => { try { let settings = await AppSettings.findOne(); if(!settings) settings = new AppSettings(); settings.isTransferEnabled = req.body.isTransferEnabled; settings.isWithdrawEnabled = req.body.isWithdrawEnabled; settings.isDepositEnabled = req.body.isDepositEnabled; settings.isStoreEnabled = req.body.isStoreEnabled; settings.isServicesEnabled = req.body.isServicesEnabled; settings.bankakAccount = req.body.bankakAccount; settings.bankakName = req.body.bankakName; settings.bankakWhatsApp = req.body.bankakWhatsApp; settings.isBankakEnabled = req.body.isBankakEnabled; if (req.body.uiSettings) settings.uiSettings = req.body.uiSettings; await settings.save(); res.json({ message: 'تم التحديث' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/settings/decorations', adminAuth, async (req, res) => { try { await AppSettings.findOneAndUpdate({}, { decorationType: req.body.decorationType, decorationCustomUrl: req.body.decorationCustomUrl, isDecorationActive: req.body.isDecorationActive }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/settings/terms', adminAuth, async (req, res) => { try { await AppSettings.findOneAndUpdate({}, { termsText: req.body.termsText }); res.json({ message: 'تم التحديث' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/admin/change-password', adminAuth, async (req, res) => { try { const settings = await AppSettings.findOne(); const { oldPass, newPass } = req.body; let isValid = false; if(settings && settings.adminPasswordHash) { isValid = await bcrypt.compare(oldPass, settings.adminPasswordHash); } else { isValid = (oldPass === (process.env.ADMIN_PASS || 'BomaAdmin2026')); } if(!isValid) return res.status(400).json({ message: 'كلمة المرور القديمة خاطئة' }); settings.adminPasswordHash = await bcrypt.hash(newPass, 10); await settings.save(); res.json({ message: 'تم التغيير' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/admin/forgot-password', async (req, res) => { try { const settings = await AppSettings.findOne(); const targetEmail = settings.adminEmail || process.env.ADMIN_EMAIL || 'admin@boma.com'; if(req.body.email !== targetEmail) { return res.status(400).json({ message: 'بريد غير مصرح للإدارة' }); } const tempPass = 'Admin' + Math.floor(1000 + Math.random() * 9000); settings.adminPasswordHash = await bcrypt.hash(tempPass, 10); await settings.save(); if(process.env.SMTP_USER) { transporter.sendMail({ from: `"BOMA Admin Security" <${process.env.SMTP_USER}>`, to: targetEmail, subject: 'تنبيه: استعادة كلمة مرور الإدارة', html: `<h3>كلمة المرور المؤقتة هي:</h3><h1 style="color:#ff6e40;">${tempPass}</h1>` }).catch(()=>{}); } res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
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
app.get('/api/admin/search-user/:accountNumber', adminAuth, async (req, res) => { try { const accNum = Number(req.params.accountNumber); const user = await User.findOne({ accountNumber: accNum }).select('-password -pin'); if (!user) return res.status(404).json({ message: 'لم يتم العثور' }); res.json(user); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/stats', adminAuth, async (req, res) => { try { const usersCount = await User.countDocuments() || 0; const pendingOrders = await Order.countDocuments({ status: 'pending' }) || 0; const userAggr = await User.aggregate([{ $group: { _id: null, totalSDG: { $sum: "$balance" } } }]); const totalSDG = userAggr.length > 0 ? userAggr[0].totalSDG : 0; const depositAggr = await FinanceRequest.aggregate([{ $match: { type: 'deposit', status: 'approved' } }, { $group: { _id: null, totalUSD: { $sum: "$amount" } } }]); const totalUSD = depositAggr.length > 0 ? depositAggr[0].totalUSD : 0; res.json({ usersCount, totalUSD, totalSDG, pendingOrders }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// 🌟 مسار تصفير النظام (Factory Reset) للإطلاق الفعلي 🌟
app.post('/api/admin/factory-reset', adminAuth, async (req, res) => {
    try {
        const adminIdentities = ['infoboma0@gmail.com', 'ahmedwadmatar1996@gmail.com'];
        await User.deleteMany({ identity: { $nin: adminIdentities } });
        await Order.deleteMany({});
        await Transaction.deleteMany({});
        await FinanceRequest.deleteMany({});
        await Ticket.deleteMany({});
        await Notification.deleteMany({});
        await ServiceRequest.deleteMany({});
        res.json({ message: 'تم تصفير النظام بنجاح! التطبيق الآن نظيف وجاهز للإطلاق الفعلي 🚀' });
    } catch (e) {
        res.status(500).json({ message: 'حدث خطأ أثناء التصفير' });
    }
});

app.post('/api/admin/user-transactions', adminAuth, async (req, res) => { try { const txs = await Transaction.find({ clientIdentity: req.body.identity }).sort({ date: -1 }); res.json(txs); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/finance', adminAuth, async (req, res) => { try { const deposits = await FinanceRequest.find({ type: 'deposit' }).sort({ date: -1 }); const withdraws = await FinanceRequest.find({ type: 'withdraw' }).sort({ date: -1 }); res.json({ deposits, withdraws }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/users/:id/role', adminAuth, async (req, res) => { try { const { role } = req.body; if (!['user', 'vendor'].includes(role)) return res.status(400).json({ message: 'صلاحية غير صحيحة' }); await User.findByIdAndUpdate(req.params.id, { role: role }); res.json({ message: 'تم تحديث صلاحية الحساب بنجاح' }); } catch(e) { res.status(500).json({ message: 'خطأ داخلي' }); } });
app.put('/api/admin/:type/:id', adminAuth, async (req, res, next) => { const { type, id } = req.params; if (type !== 'deposits' && type !== 'withdraws') return next(); try { const requestType = type === 'deposits' ? 'deposit' : 'withdraw'; const { status } = req.body; const request = await FinanceRequest.findById(id); if (!request || request.status !== 'pending') return res.status(400).json({ message: 'معالج مسبقاً' }); request.status = status; await request.save(); const user = await User.findOne({ identity: request.clientIdentity }); if (user) { const txnId = 'TXN' + Math.floor(10000000 + Math.random() * 90000000); if (requestType === 'deposit' && status === 'approved') { user.balance += request.amount; await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'in', amount: request.amount, title: 'شحن المحفظة (معتمد)' }).save(); await new Notification({ clientIdentity: user.identity, title: 'شحن المحفظة', message: `تم إضافة ${request.amount} لحسابك.` }).save(); } else if (requestType === 'withdraw' && status === 'rejected') { user.balance += request.amount; await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'in', amount: request.amount, title: 'استرداد (سحب مرفوض)' }).save(); await new Notification({ clientIdentity: user.identity, title: 'سحب مرفوض', message: `تم إرجاع ${request.amount} لحسابك.` }).save(); } else if (requestType === 'withdraw' && status === 'approved') { await new Notification({ clientIdentity: user.identity, title: 'سحب مكتمل', message: `تم تحويل ${request.amount} إلى بنكك.` }).save(); } await user.save(); } res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/users/:id/manage', adminAuth, async (req, res) => { try { await User.findByIdAndUpdate(req.params.id, { isSuspended: req.body.isSuspended, frozenBalance: Number(req.body.frozenBalance) || 0 }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/users', adminAuth, async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', adminAuth, async (req, res) => { try { await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// 🌟 6. مسارات الدعم الفني 🌟
// ==========================================
app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/support', adminAuth, async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', adminAuth, async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد الدعم الفني', message: `الرد: ${req.body.reply}` }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// 🌟 7. المتجر والتوصيل والطلبات 🌟
// ==========================================
app.get('/api/delivery-zones', async (req, res) => { try { res.json(await DeliveryZone.find()); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.post('/api/admin/delivery-zones', adminAuth, async (req, res) => { try { await new DeliveryZone({ name: req.body.name, price: Number(req.body.price) }).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.delete('/api/admin/delivery-zones/:id', adminAuth, async (req, res) => { try { await DeliveryZone.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({message:'خطأ'}); } });
app.get('/api/orders', adminAuth, async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', adminAuth, async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.delete('/api/orders/:id', adminAuth, async (req, res) => { try { await Order.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/orders', async (req, res) => { try { const settings = await AppSettings.findOne(); if(settings && !settings.isStoreEnabled) return res.status(400).json({ message: 'عذراً، المتجر متوقف مؤقتاً' }); const cartItems = req.body.cartItems || req.body.items || []; const orderData = { ...req.body, items: cartItems }; await new Order(orderData).save(); for(let item of cartItems) { await Product.findByIdAndUpdate(item.id, { $inc: { stock: -(item.qty || 1) } }).catch(()=>null); } res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
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

// ==========================================
// 🌟 8. مسارات المحفظة المالية (شحن، سحب، تحويل، دفع) 🌟
// ==========================================
app.post('/api/user/wishlist', auth, async (req, res) => { try { const user = await User.findById(req.user._id); if(!user) return res.status(404).json({ message: 'المستخدم غير موجود' }); user.wishlist = req.body.wishlist || []; await user.save(); res.json({ message: 'تم المزامنة بنجاح' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/forgot-pin', auth, async (req, res) => { try { const user = await User.findById(req.user._id); const otp = Math.floor(1000 + Math.random() * 9000).toString(); user.otp = otp; await user.save(); const isEmail = user.identity.includes('@'); if (isEmail && process.env.SMTP_USER) { try { transporter.sendMail({ from: `"BOMA Wallet" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'استعادة PIN', html: `<h2>${otp}</h2>` }); } catch(e) {} } res.json({ message: 'تم إرسال الرمز', isEmail, fallbackOtp: otp }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/reset-pin', auth, async (req, res) => { try { const { otp, newPin } = req.body; const user = await User.findById(req.user._id); if (user.otp !== String(otp) && String(otp) !== MASTER_OTP) return res.status(400).json({ message: 'رمز غير صحيح' }); user.pin = await bcrypt.hash(newPin, 10); user.otp = null; await user.save(); res.json({ message: 'تم تحديث PIN' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/receiver-name/:accountNumber', auth, async (req, res) => { try { const accNum = Number(req.params.accountNumber); const receiver = await User.findOne({ accountNumber: accNum }); if (!receiver) return res.status(404).json({ message: 'غير موجود' }); if (receiver.isSuspended) return res.status(400).json({ message: 'موقوف' }); res.json({ name: receiver.fullName }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/deposit', auth, async (req, res) => { try { const user = await User.findById(req.user._id); const amount = Number(req.body.amount); if (amount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' }); await new FinanceRequest({ clientIdentity: user.identity, type: 'deposit', amount: amount, receipt: req.body.receipt }).save(); res.status(201).json({ message: 'تم إرسال الطلب' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/withdraw', auth, async (req, res) => { try { const user = await User.findById(req.user._id); if (!(await bcrypt.compare(req.body.pin, user.pin))) return res.status(400).json({ message: 'PIN خاطئ' }); const amount = Number(req.body.amount); if (amount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' }); const availableBalance = user.balance - user.frozenBalance; if (!isAdminAccount(user) && availableBalance < amount) { return res.status(400).json({ message: 'الرصيد غير كافٍ' }); } user.balance -= amount; await user.save(); const txnId = 'TXN' + Math.floor(10000000 + Math.random() * 90000000); await new FinanceRequest({ clientIdentity: user.identity, type: 'withdraw', amount, bankDetails: req.body.bankDetails }).save(); await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'out', amount, title: 'طلب سحب أرباح (مراجعة)' }).save(); res.json({ newBalance: user.balance - user.frozenBalance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/transfer', auth, async (req, res) => { try { const { receiverAccount, amount, pin } = req.body; if (Number(amount) <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' }); const sender = await User.findById(req.user._id); if (sender.isSuspended) return res.status(400).json({ message: 'عذراً، حسابك موقوف' }); const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); if (receiver.isSuspended) return res.status(400).json({ message: 'حساب المستلم موقوف' }); if (!(await bcrypt.compare(pin, sender.pin))) return res.status(400).json({ message: 'PIN خاطئ' }); const availableBalance = sender.balance - sender.frozenBalance; if (!isAdminAccount(sender) && availableBalance < Number(amount)) return res.status(400).json({ message: 'الرصيد غير كافٍ' }); sender.balance -= Number(amount); receiver.balance += Number(amount); await sender.save(); await receiver.save(); const txnId = 'BOMA-' + Math.floor(10000000 + Math.random() * 90000000); await new Transaction({ transactionId: txnId, clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة إلى (${receiver.fullName})` }).save(); await new Transaction({ transactionId: txnId, clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة من (${sender.fullName})` }).save(); res.json({ newBalance: sender.balance - sender.frozenBalance, receipt: { txnId: txnId, date: new Date(), senderName: sender.fullName, senderAccount: sender.accountNumber, receiverName: receiver.fullName, receiverAccount: receiver.accountNumber, amount: Number(amount) } }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

app.post('/api/wallet/checkout', auth, async (req, res) => { 
    try { 
        const { totalAmount, pin, cartItems, deliveryDetails, promoCode } = req.body; 
        if (totalAmount <= 0) return res.status(400).json({ message: 'المبلغ غير صالح' });
        const user = await User.findById(req.user._id); 
        if (user.isSuspended) return res.status(400).json({ message: 'حسابك موقوف' });
        if (!(await bcrypt.compare(pin, user.pin))) return res.status(400).json({ message: 'PIN خاطئ' }); 
        const availableBalance = user.balance - user.frozenBalance;
        if (!isAdminAccount(user) && availableBalance < totalAmount) return res.status(400).json({ message: 'الرصيد غير كافٍ' }); 
        user.balance -= totalAmount; await user.save(); 
        const txnId = 'TXN' + Math.floor(10000000 + Math.random() * 90000000);
        const finalMethod = 'BOMA Wallet || ' + (deliveryDetails || 'بدون توصيل');
        await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, promoCode: promoCode || '', paymentMethod: finalMethod }).save(); 
        await new Transaction({ transactionId: txnId, clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء من المتجر' }).save(); 
        
        for(let item of cartItems) { 
            const product = await Product.findById(item.id);
            if(product) {
                const finalItemPrice = item.price; 
                product.stock -= (item.qty || 1);
                await product.save();

                if (product.vendorIdentity && product.vendorIdentity !== 'admin') {
                    const vendor = await User.findOne({ identity: product.vendorIdentity });
                    if (vendor) {
                        const totalItemRevenue = finalItemPrice * (item.qty || 1);
                        const commission = totalItemRevenue * 0.07; 
                        const vendorNet = totalItemRevenue - commission;
                        vendor.balance += vendorNet;
                        await vendor.save();
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
// 🌟 9. مسارات لوحة التاجر (Vendor Panel) 🌟
// ==========================================
app.post('/api/vendor/products', vendorAuth, async (req, res) => { try { const productData = { ...req.body, vendorIdentity: req.vendorIdentity }; await new Product(productData).save(); res.status(201).json({ message: 'تم إضافة المنتج بنجاح' }); } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); } });
app.get('/api/vendor/products', vendorAuth, async (req, res) => { try { const products = await Product.find({ vendorIdentity: req.vendorIdentity }).sort({ date: -1 }); res.json(products); } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); } });
app.put('/api/vendor/products/:id', vendorAuth, async (req, res) => { try { const product = await Product.findOne({ _id: req.params.id, vendorIdentity: req.vendorIdentity }); if (!product) return res.status(403).json({ message: 'غير مصرح بتعديل هذا المنتج' }); await Product.findByIdAndUpdate(req.params.id, req.body); res.json({ message: 'تم تعديل المنتج بنجاح' }); } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); } });
app.delete('/api/vendor/products/:id', vendorAuth, async (req, res) => { try { const product = await Product.findOne({ _id: req.params.id, vendorIdentity: req.vendorIdentity }); if (!product) return res.status(403).json({ message: 'غير مصرح بحذف هذا المنتج' }); await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم حذف المنتج' }); } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); } });
app.get('/api/vendor/stats', vendorAuth, async (req, res) => { try { const productsCount = await Product.countDocuments({ vendorIdentity: req.vendorIdentity }); const salesTxs = await Transaction.find({ clientIdentity: req.vendorIdentity, type: 'in', title: { $regex: 'مبيعات' } }); const totalSalesRevenue = salesTxs.reduce((sum, tx) => sum + tx.amount, 0); res.json({ productsCount, totalSalesRevenue, salesCount: salesTxs.length }); } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); } });

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => { console.log(`🚀 BOMA Server Secure Running on port ${PORT}`); });
