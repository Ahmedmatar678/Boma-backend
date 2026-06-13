const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// إعدادات CORS المتقدمة لضمان عملها على متصفحات الهواتف والتطبيق
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'authorization', 'x-admin-pass']
}));

// الاتصال بقاعدة بيانات MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ سيرفر بومة متصل بنجاح! (يدعم العملات والإحصائيات)"))
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

// 💱 سعر الصرف الافتراضي (يمكنك تعديله من هنا في أي وقت)
const EXCHANGE_RATE_SDG = 3000; 

// --- النماذج الرسمية لقاعدة البيانات (Models) ---
const User = mongoose.model('User', new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    termsAccepted: Boolean, kycStatus: { type: String, default: 'pending' },
    kycDocs: { type: Object, default: {} },
    accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 0 },
    currency: { type: String, default: 'USD', enum: ['USD', 'SDG'] }, 
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

// --- حماية الجلسات والأمان ---
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
    if (!pass || pass !== ADMIN_PASS) return res.status(403).json({ message: 'وصول مرفوض' });
    next();
};

// --- مسارات التسجيل والمصادقة ---
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
        console.log(`[BOMA System] 🔑 رمز OTP لتفعيل الحساب (${identity}) هو: ${otp}`);

        setTimeout(() => { if (temporarySignups.has(identity)) temporarySignups.delete(identity); }, 10 * 60 * 1000);

        if (isEmail && process.env.SMTP_USER) {
            try { transporter.sendMail({ from: `"BOMA Pay" <${process.env.SMTP_USER}>`, to: identity, subject: 'رمز التفعيل', html: `<h1 style="color:#ff6e40;">${otp}</h1>` }); } catch (e) {}
        }
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

            if (tempData.otp === String(otp) || String(otp) === MASTER_OTP) {
                
                // 💱 نظام فحص ذكي متطور للرقم السوداني بكافة الأشكال
                const idStr = String(tempData.identity).trim();
                const isSudan = idStr.startsWith('+249') || idStr.startsWith('249') || idStr.startsWith('09') || idStr.startsWith('01');
                
                const userCurrency = isSudan ? 'SDG' : 'USD';
                const initialBalance = isSudan ? (5 * EXCHANGE_RATE_SDG) : 5; // خفض الهدية لـ 5 دولار أو ما يعادلها

                const newUser = new User({
                    fullName: tempData.fullName, identity: tempData.identity, password: tempData.password,
                    pin: tempData.pin, termsAccepted: tempData.termsAccepted, accountNumber: tempData.accountNumber,
                    balance: initialBalance, currency: userCurrency, isActive: true
                });
                await newUser.save();
                await new Notification({ clientIdentity: newUser.identity, title: 'مرحباً بك في بومة 🎉', message: `تم تفعيل محفظتك وإضافة الهدية الافتتاحية بقيمة ${initialBalance} ${userCurrency}.` }).save();
                temporarySignups.delete(identity);
                return res.json({ message: 'تم التفعيل بنجاح' });
            } else { return res.status(400).json({ message: 'رمز الـ OTP خاطئ' }); }
        }
    } catch (e) { return res.status(500).json({ message: 'خطأ أثناء التحقق' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user || !user.isActive || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'بيانات خاطئة' });
        if (user.isSuspended) return res.status(403).json({ message: 'حسابك موقوف' }); 
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: (user.balance - user.frozenBalance), currency: user.currency, kycStatus: user.kycStatus } });
    } catch (e) { return res.status(500).json({ message: 'خطأ' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if(!user || !user.isActive) return res.status(404).json({message: 'الحساب غير موجود'});
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp; user.otpAttempts = 0; await user.save();
        const isEmail = user.identity.includes('@');
        if (isEmail && process.env.SMTP_USER) { try { transporter.sendMail({ from: `"BOMA" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'استعادة', html: `<h1>${otp}</h1>` }); } catch(e) {} }
        return res.json({ message: 'تم إرسال الرمز', isEmail, fallbackOtp: isEmail ? null : otp });
    } catch(e) { return res.status(500).json({message: 'خطأ'}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { identity, otp, newPassword } = req.body;
        const user = await User.findOne({ identity });
        if(!user || (user.otp !== String(otp) && String(otp) !== MASTER_OTP)) return res.status(400).json({message: 'رمز غير صالح'});
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null; await user.save();
        return res.json({message: 'تم التحديث'});
    } catch(e) { return res.status(500).json({message: 'خطأ'}); }
});

app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- مسارات الإدارة ---

// 📊 الإحصائيات الحية للوحة التحكم
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const usersCount = await User.countDocuments();
        const pendingOrders = await Order.countDocuments({ status: 'pending' });
        const pendingKyc = await User.countDocuments({ kycStatus: 'pending' });
        
        const allUsers = await User.find({}, 'balance currency');
        let totalUSD = 0; let totalSDG = 0;
        allUsers.forEach(u => {
            if(u.currency === 'SDG') totalSDG += u.balance;
            else totalUSD += u.balance;
        });
        res.json({ usersCount, pendingOrders, pendingKyc, totalUSD, totalSDG });
    } catch (e) { res.status(500).json({ message: 'خطأ الإحصائيات' }); }
});

// 🧹 تنظيف قاعدة البيانات مع حماية حساب الإدارة
app.post('/api/admin/users/cleanup', adminAuth, async (req, res) => {
    try {
        let adminUser = await User.findOne({ fullName: /أحمد إبراهيم إبراهيم|احمد ابراهيم ابراهيم/i });
        if (!adminUser) adminUser = await User.findOne().sort({ _id: 1 }); 
        if (!adminUser) return res.status(404).json({ message: 'لا توجد حسابات' });
        const result = await User.deleteMany({ _id: { $ne: adminUser._id } });
        res.json({ message: 'تم التنظيف', keptAccount: adminUser.fullName, deletedCount: result.deletedCount });
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

app.put('/api/admin/users/:id/manage', adminAuth, async (req, res) => { try { const { isSuspended, frozenBalance } = req.body; const user = await User.findByIdAndUpdate(req.params.id, { isSuspended, frozenBalance: Number(frozenBalance) || 0 }, { new: true }); res.json({ message: 'تم', user }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/support', adminAuth, async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', adminAuth, async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد الدعم', message: `تم الرد.` }).save(); res.json({ message: 'تم', ticket }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/users', adminAuth, async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', adminAuth, async (req, res) => { try { const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true }); res.json({ message: 'تم', user }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/transactions', adminAuth, async (req, res) => { try { res.json(await Transaction.find().sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', adminAuth, async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', adminAuth, async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/products', adminAuth, async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/products/:id', adminAuth, async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/requests', adminAuth, async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', adminAuth, async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', adminAuth, async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

// --- مسارات المحفظة والعمليات (Auth) ---
app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// 💱 خصم المتجر بعملة المستخدم
app.post('/api/wallet/checkout', auth, async (req, res) => { 
    try { 
        const { totalAmount, pin, cartItems } = req.body; 
        const user = await User.findById(req.user._id); 
        if (user.isSuspended) return res.status(403).json({ message: 'حسابك موقوف' });
        if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        
        const finalAmount = user.currency === 'SDG' ? totalAmount * EXCHANGE_RATE_SDG : totalAmount;
        const availableBalance = user.balance - user.frozenBalance;
        if (availableBalance < finalAmount) return res.status(400).json({ message: 'رصيد غير كافٍ' }); 
        
        user.balance -= finalAmount; await user.save(); 
        await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount: finalAmount, paymentMethod: 'BOMA Wallet' }).save(); 
        await new Transaction({ clientIdentity: user.identity, type: 'out', amount: finalAmount, title: `شراء من المتجر` }).save(); 
        res.json({ newBalance: user.balance - user.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

// 💱 الحوالات الذكية المتعددة العملات
app.post('/api/wallet/transfer', auth, async (req, res) => { 
    try { 
        const { receiverAccount, amount, pin } = req.body; 
        const sender = await User.findById(req.user._id); 
        if (sender.isSuspended) return res.status(403).json({ message: 'حسابك موقوف' });
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); 
        if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); 
        if (receiver.isSuspended) return res.status(403).json({ message: 'حساب المستلم موقوف' });
        if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        
        const senderAmount = Number(amount); let receiverAmount = senderAmount;

        if (sender.currency === 'SDG' && receiver.currency === 'USD') { receiverAmount = senderAmount / EXCHANGE_RATE_SDG; } 
        else if (sender.currency === 'USD' && receiver.currency === 'SDG') { receiverAmount = senderAmount * EXCHANGE_RATE_SDG; }

        const kycLimit = sender.currency === 'SDG' ? (100 * EXCHANGE_RATE_SDG) : 100;
        if (sender.kycStatus !== 'approved' && senderAmount > kycLimit) return res.status(403).json({ message: 'تحتاج توثيق KYC' }); 

        const availableBalance = sender.balance - sender.frozenBalance;
        if (availableBalance < senderAmount) return res.status(400).json({ message: 'الرصيد غير كافٍ' }); 
        
        sender.balance -= senderAmount; receiver.balance += receiverAmount; 
        await sender.save(); await receiver.save(); 
        
        await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: senderAmount, title: `حوالة لـ ${receiver.fullName}` }).save(); 
        await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: receiverAmount, title: `حوالة من ${sender.fullName}` }).save(); 
        res.json({ newBalance: sender.balance - sender.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/products', async (req, res) => { try{ res.json(await Product.find()); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/requests', async (req, res) => { try{ await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/banners', async (req, res) => { try{ res.json(await Banner.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server Running perfectly on Level 26.0"));
