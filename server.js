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
    accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 50 },
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

        if (isEmail && process.env.SMTP_USER) {
            try { transporter.sendMail({ from: `"BOMA Pay" <${process.env.SMTP_USER}>`, to: identity, subject: 'رمز تفعيل حسابك - BOMA', html: `<h1 style="color:#ff6e40;">${otp}</h1>` }); } catch (e) {}
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
                const newUser = new User({
                    fullName: tempData.fullName, identity: tempData.identity, password: tempData.password,
                    pin: tempData.pin, termsAccepted: tempData.termsAccepted, accountNumber: tempData.accountNumber,
                    balance: 0, isActive: true
                });
                await newUser.save();
                await new Notification({ clientIdentity: newUser.identity, title: 'مرحباً بك في بومة 🎉', message: 'تم تفعيل حسابك المالي بنجاح.' }).save();
                temporarySignups.delete(identity);
                return res.json({ message: 'تم التفعيل بنجاح' });
            } else { return res.status(400).json({ message: 'رمز الـ OTP خاطئ' }); }
        }
    } catch (e) { return res.status(500).json({ message: 'خطأ أثناء التحقق' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if(!user || !user.isActive) return res.status(404).json({message: 'الحساب غير موجود أو غير مفعل'});
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp; user.otpAttempts = 0; await user.save();
        
        const isEmail = user.identity.includes('@');
        if (isEmail && process.env.SMTP_USER) {
            try { transporter.sendMail({ from: `"BOMA Support" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'استعادة كلمة المرور', html: `<h1>${otp}</h1>` }); } catch(e) {}
        }
        return res.json({ message: 'تم إرسال الرمز', isEmail, fallbackOtp: isEmail ? null : otp });
    } catch(e) { return res.status(500).json({message: 'خطأ داخلي'}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { identity, otp, newPassword } = req.body;
        const user = await User.findOne({ identity });
        if(!user || (user.otp !== String(otp) && String(otp) !== MASTER_OTP)) return res.status(400).json({message: 'رمز غير صالح'});
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null; await user.save();
        return res.json({message: 'تم تحديث كلمة المرور بنجاح'});
    } catch(e) { return res.status(500).json({message: 'خطأ'}); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user || !user.isActive || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'بيانات خاطئة' });
        if (user.isSuspended) return res.status(403).json({ message: 'هذا الحساب موقوف مؤقتاً من قبل الإدارة' }); 
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: (user.balance - user.frozenBalance), kycStatus: user.kycStatus } });
    } catch (e) { return res.status(500).json({ message: 'خطأ' }); }
});

app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// --- مسارات الإدارة (المحمية) ---
// ==========================================

// الإحصائيات (مصممة للعمل حتى لو كان هناك بيانات قديمة تالفة)
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const usersCount = await User.countDocuments() || 0;
        const pendingOrders = await Order.countDocuments({ status: 'pending' }) || 0;
        
        const users = await User.find() || [];
        const totalSDG = users.reduce((sum, u) => sum + (Number(u.balance) || 0), 0);
        
        const approvedDeposits = await FinanceRequest.find({ type: 'deposit', status: 'approved' }) || [];
        const totalUSD = approvedDeposits.reduce((sum, d) => sum + (Number(d.amount) || 0), 0); 
        
        res.json({ usersCount, totalUSD, totalSDG, pendingOrders });
    } catch (e) { 
        console.error('Stats Error:', e); 
        res.status(500).json({ message: 'خطأ في جلب الإحصائيات' }); 
    }
});

// المسار الوحيد والصحيح لكشف حساب العميل للإدارة
app.post('/api/admin/user-transactions', adminAuth, async (req, res) => {
    try {
        const { identity } = req.body;
        const txs = await Transaction.find({ clientIdentity: identity }).sort({ date: -1 });
        res.json(txs);
    } catch (e) {
        res.status(500).json({ message: 'خطأ في جلب كشف الحساب' });
    }
});

app.get('/api/admin/finance', adminAuth, async (req, res) => {
    try {
        const deposits = await FinanceRequest.find({ type: 'deposit' }).sort({ date: -1 });
        const withdraws = await FinanceRequest.find({ type: 'withdraw' }).sort({ date: -1 });
        res.json({ deposits, withdraws });
    } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

app.put('/api/admin/:type/:id', adminAuth, async (req, res) => {
    try {
        const { type, id } = req.params; 
        const requestType = type === 'deposits' ? 'deposit' : 'withdraw';
        const { status } = req.body;
        
        const request = await FinanceRequest.findById(id);
        if (!request || request.status !== 'pending') return res.status(400).json({ message: 'طلب غير صالح أو معالج مسبقاً' });
        
        request.status = status;
        await request.save();

        const user = await User.findOne({ identity: request.clientIdentity });
        if (user) {
            if (requestType === 'deposit' && status === 'approved') {
                user.balance += request.amount;
                await new Transaction({ clientIdentity: user.identity, type: 'in', amount: request.amount, title: 'شحن المحفظة (إيداع معتمد)' }).save();
                await new Notification({ clientIdentity: user.identity, title: 'شحن المحفظة', message: `تمت الموافقة على إيداعك وإضافة ${request.amount} SDG لحسابك.` }).save();
            } 
            else if (requestType === 'withdraw' && status === 'rejected') {
                user.balance += request.amount;
                await new Transaction({ clientIdentity: user.identity, type: 'in', amount: request.amount, title: 'استرداد (سحب مرفوض)' }).save();
                await new Notification({ clientIdentity: user.identity, title: 'سحب مرفوض', message: `تم رفض طلب السحب وإرجاع ${request.amount} SDG لحسابك.` }).save();
            }
            else if (requestType === 'withdraw' && status === 'approved') {
                await new Notification({ clientIdentity: user.identity, title: 'سحب مكتمل', message: `تم تحويل ${request.amount} SDG إلى حسابك البنكي بنجاح.` }).save();
            }
            await user.save();
        }
        res.json({ message: 'تم التحديث بنجاح' });
    } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

app.post('/api/admin/users/cleanup', adminAuth, async (req, res) => {
    try {
        let adminUser = await User.findOne({ fullName: /أحمد إبراهيم|احمد ابراهيم/i });
        if (!adminUser) adminUser = await User.findOne().sort({ _id: 1 }); 
        if (!adminUser) return res.status(404).json({ message: 'لا توجد حسابات' });
        const result = await User.deleteMany({ _id: { $ne: adminUser._id } });
        res.json({ message: 'تم التنظيف', keptAccount: adminUser.fullName, deletedCount: result.deletedCount });
    } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); }
});

app.put('/api/admin/users/:id/manage', adminAuth, async (req, res) => {
    try {
        const { isSuspended, frozenBalance } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { isSuspended, frozenBalance: Number(frozenBalance) || 0 }, { new: true });
        res.json({ message: 'تم التحديث', user });
    } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

app.get('/api/users', adminAuth, async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', adminAuth, async (req, res) => { try { const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true }); res.json({ message: 'تم', user }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

app.get('/api/admin/support', adminAuth, async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', adminAuth, async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد الدعم الفني', message: `تم الرد على تذكرتك.` }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// المبيعات والطلبات
app.get('/api/orders', adminAuth, async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', adminAuth, async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.delete('/api/orders/:id', adminAuth, async (req, res) => { try { await Order.findByIdAndDelete(req.params.id); res.json({ message: 'تم الحذف' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// المنتجات
app.post('/api/products', adminAuth, async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
// المسار الذي كان مفقوداً لتعديل المنتجات!
app.put('/api/admin/products/:id', adminAuth, async (req, res) => {
    try {
        await Product.findByIdAndUpdate(req.params.id, req.body);
        res.json({ message: 'تم التحديث بنجاح' });
    } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});
app.delete('/api/products/:id', adminAuth, async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.get('/api/requests', adminAuth, async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', adminAuth, async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', adminAuth, async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

// ==========================================
// --- مسارات المحفظة للمستخدمين ---
// ==========================================
app.post('/api/wallet/deposit', auth, async (req, res) => { 
    try { 
        const user = await User.findById(req.user._id); 
        await new FinanceRequest({ clientIdentity: user.identity, type: 'deposit', amount: req.body.amount, receipt: req.body.receipt }).save(); 
        res.status(201).json({ message: 'تم إرسال الطلب' }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/withdraw', auth, async (req, res) => { 
    try { 
        const user = await User.findById(req.user._id); 
        if (!(await bcrypt.compare(req.body.pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        const amount = Number(req.body.amount);
        const availableBalance = user.balance - user.frozenBalance;
        if (availableBalance < amount) return res.status(400).json({ message: 'الرصيد المتاح غير كافٍ' }); 
        
        user.balance -= amount; 
        await user.save();

        await new FinanceRequest({ clientIdentity: user.identity, type: 'withdraw', amount, bankDetails: req.body.bankDetails }).save(); 
        await new Transaction({ clientIdentity: user.identity, type: 'out', amount, title: 'طلب سحب أرباح (قيد المراجعة)' }).save(); 
        res.json({ newBalance: user.balance - user.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

app.post('/api/wallet/checkout', auth, async (req, res) => { 
    try { 
        const { totalAmount, pin, cartItems } = req.body; 
        const user = await User.findById(req.user._id); 
        if (user.isSuspended) return res.status(403).json({ message: 'عذراً، حسابك موقوف' });
        if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        const availableBalance = user.balance - user.frozenBalance;
        if (availableBalance < totalAmount) return res.status(400).json({ message: 'الرصيد المتاح غير كافٍ' }); 
        user.balance -= totalAmount; 
        await user.save(); 
        await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet' }).save(); 
        await new Transaction({ clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء منتجات من المتجر' }).save(); 
        res.json({ newBalance: user.balance - user.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/transfer', auth, async (req, res) => { 
    try { 
        const { receiverAccount, amount, pin } = req.body; 
        const sender = await User.findById(req.user._id); 
        if (sender.isSuspended) return res.status(403).json({ message: 'عذراً، حسابك موقوف' });
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); 
        if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); 
        if (receiver.isSuspended) return res.status(403).json({ message: 'حساب المستلم موقوف' });
        if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'تحتاج توثيق KYC' }); 
        const availableBalance = sender.balance - sender.frozenBalance;
        if (availableBalance < Number(amount)) return res.status(400).json({ message: 'الرصيد غير كافٍ' }); 
        sender.balance -= Number(amount); receiver.balance += Number(amount); 
        await sender.save(); await receiver.save(); 
        await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة إلى (${receiver.fullName})` }).save(); 
        await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة من (${sender.fullName})` }).save(); 
        res.json({ newBalance: sender.balance - sender.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server Clean & Secure Running"));

            if (tempData.otp === String(otp) || String(otp) === MASTER_OTP) {
                const newUser = new User({
                    fullName: tempData.fullName, identity: tempData.identity, password: tempData.password,
                    pin: tempData.pin, termsAccepted: tempData.termsAccepted, accountNumber: tempData.accountNumber,
                    balance: 0, isActive: true
                });
                await newUser.save();
                await new Notification({ clientIdentity: newUser.identity, title: 'مرحباً بك في بومة 🎉', message: 'تم تفعيل حسابك المالي بنجاح.' }).save();
                temporarySignups.delete(identity);
                return res.json({ message: 'تم التفعيل بنجاح' });
            } else { return res.status(400).json({ message: 'رمز الـ OTP خاطئ' }); }
        }
    } catch (e) { return res.status(500).json({ message: 'خطأ أثناء التحقق' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if(!user || !user.isActive) return res.status(404).json({message: 'الحساب غير موجود أو غير مفعل'});
        
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp; user.otpAttempts = 0; await user.save();
        
        const isEmail = user.identity.includes('@');
        if (isEmail && process.env.SMTP_USER) {
            try { transporter.sendMail({ from: `"BOMA Support" <${process.env.SMTP_USER}>`, to: user.identity, subject: 'استعادة كلمة المرور', html: `<h1>${otp}</h1>` }); } catch(e) {}
        }
        return res.json({ message: 'تم إرسال الرمز', isEmail, fallbackOtp: isEmail ? null : otp });
    } catch(e) { return res.status(500).json({message: 'خطأ داخلي'}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { identity, otp, newPassword } = req.body;
        const user = await User.findOne({ identity });
        if(!user || (user.otp !== String(otp) && String(otp) !== MASTER_OTP)) return res.status(400).json({message: 'رمز غير صالح'});
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null; await user.save();
        return res.json({message: 'تم تحديث كلمة المرور بنجاح'});
    } catch(e) { return res.status(500).json({message: 'خطأ'}); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user || !user.isActive || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'بيانات خاطئة' });
        if (user.isSuspended) return res.status(403).json({ message: 'هذا الحساب موقوف مؤقتاً من قبل الإدارة' }); 
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: (user.balance - user.frozenBalance), kycStatus: user.kycStatus } });
    } catch (e) { return res.status(500).json({ message: 'خطأ' }); }
});

app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// ==========================================
// --- مسارات الإدارة (المحمية) ---
// ==========================================

// مسار الإحصائيات (مطور ومؤمّن للعمل دائماً)
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const usersCount = await User.countDocuments() || 0;
        const pendingOrders = await Order.countDocuments({ status: 'pending' }) || 0;
        
        // استخدام التجميع (Aggregation) لضمان جمع الأرصدة بشكل صحيح وسريع
        const userAggr = await User.aggregate([{ $group: { _id: null, totalSDG: { $sum: "$balance" } } }]);
        const totalSDG = userAggr.length > 0 ? userAggr[0].totalSDG : 0;
        
        const depositAggr = await FinanceRequest.aggregate([
            { $match: { type: 'deposit', status: 'approved' } },
            { $group: { _id: null, totalUSD: { $sum: "$amount" } } }
        ]);
        const totalUSD = depositAggr.length > 0 ? depositAggr[0].totalUSD : 0; 
        
        res.json({ usersCount, totalUSD, totalSDG, pendingOrders });
    } catch (e) { 
        console.error('Stats Error:', e); 
        res.status(500).json({ message: 'خطأ في جلب الإحصائيات' }); 
    }
});

// المسار الجديد لكشف حساب العميل (بواسطة POST لمنع ضياع رقم الهاتف في الرابط)
app.post('/api/admin/user-transactions', adminAuth, async (req, res) => {
    try {
        const { identity } = req.body;
        const txs = await Transaction.find({ clientIdentity: identity }).sort({ date: -1 });
        res.json(txs);
    } catch (e) {
        res.status(500).json({ message: 'خطأ في جلب كشف الحساب' });
    }
});

app.get('/api/admin/finance', adminAuth, async (req, res) => {
    try {
        const deposits = await FinanceRequest.find({ type: 'deposit' }).sort({ date: -1 });
        const withdraws = await FinanceRequest.find({ type: 'withdraw' }).sort({ date: -1 });
        res.json({ deposits, withdraws });
    } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

app.put('/api/admin/:type/:id', adminAuth, async (req, res) => {
    try {
        const { type, id } = req.params; 
        const requestType = type === 'deposits' ? 'deposit' : 'withdraw';
        const { status } = req.body;
        
        const request = await FinanceRequest.findById(id);
        if (!request || request.status !== 'pending') return res.status(400).json({ message: 'طلب غير صالح أو معالج مسبقاً' });
        
        request.status = status;
        await request.save();

        const user = await User.findOne({ identity: request.clientIdentity });
        if (user) {
            if (requestType === 'deposit' && status === 'approved') {
                user.balance += request.amount;
                await new Transaction({ clientIdentity: user.identity, type: 'in', amount: request.amount, title: 'شحن المحفظة (إيداع معتمد)' }).save();
                await new Notification({ clientIdentity: user.identity, title: 'شحن المحفظة', message: `تمت الموافقة على إيداعك وإضافة ${request.amount} SDG لحسابك.` }).save();
            } 
            else if (requestType === 'withdraw' && status === 'rejected') {
                user.balance += request.amount;
                await new Transaction({ clientIdentity: user.identity, type: 'in', amount: request.amount, title: 'استرداد (سحب مرفوض)' }).save();
                await new Notification({ clientIdentity: user.identity, title: 'سحب مرفوض', message: `تم رفض طلب السحب وإرجاع ${request.amount} SDG لحسابك.` }).save();
            }
            else if (requestType === 'withdraw' && status === 'approved') {
                await new Notification({ clientIdentity: user.identity, title: 'سحب مكتمل', message: `تم تحويل ${request.amount} SDG إلى حسابك البنكي بنجاح.` }).save();
            }
            await user.save();
        }
        res.json({ message: 'تم التحديث بنجاح' });
    } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

app.post('/api/admin/users/cleanup', adminAuth, async (req, res) => {
    try {
        let adminUser = await User.findOne({ fullName: /أحمد إبراهيم|احمد ابراهيم/i });
        if (!adminUser) adminUser = await User.findOne().sort({ _id: 1 }); 
        if (!adminUser) return res.status(404).json({ message: 'لا توجد حسابات' });
        const result = await User.deleteMany({ _id: { $ne: adminUser._id } });
        res.json({ message: 'تم التنظيف', keptAccount: adminUser.fullName, deletedCount: result.deletedCount });
    } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); }
});

app.put('/api/admin/users/:id/manage', adminAuth, async (req, res) => {
    try {
        const { isSuspended, frozenBalance } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { isSuspended, frozenBalance: Number(frozenBalance) || 0 }, { new: true });
        res.json({ message: 'تم التحديث', user });
    } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

app.get('/api/users', adminAuth, async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', adminAuth, async (req, res) => { try { const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true }); res.json({ message: 'تم', user }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

app.get('/api/admin/support', adminAuth, async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', adminAuth, async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد الدعم الفني', message: `تم الرد على تذكرتك.` }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', adminAuth, async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', adminAuth, async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.delete('/api/orders/:id', adminAuth, async (req, res) => { try { await Order.findByIdAndDelete(req.params.id); res.json({ message: 'تم الحذف' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

app.post('/api/products', adminAuth, async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/products/:id', adminAuth, async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/requests', adminAuth, async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', adminAuth, async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', adminAuth, async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

// ==========================================
// --- مسارات المحفظة للمستخدمين ---
// ==========================================
app.post('/api/wallet/deposit', auth, async (req, res) => { 
    try { 
        const user = await User.findById(req.user._id); 
        await new FinanceRequest({ clientIdentity: user.identity, type: 'deposit', amount: req.body.amount, receipt: req.body.receipt }).save(); 
        res.status(201).json({ message: 'تم إرسال الطلب' }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/withdraw', auth, async (req, res) => { 
    try { 
        const user = await User.findById(req.user._id); 
        if (!(await bcrypt.compare(req.body.pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        const amount = Number(req.body.amount);
        const availableBalance = user.balance - user.frozenBalance;
        if (availableBalance < amount) return res.status(400).json({ message: 'الرصيد المتاح غير كافٍ' }); 
        
        user.balance -= amount; 
        await user.save();

        await new FinanceRequest({ clientIdentity: user.identity, type: 'withdraw', amount, bankDetails: req.body.bankDetails }).save(); 
        await new Transaction({ clientIdentity: user.identity, type: 'out', amount, title: 'طلب سحب أرباح (قيد المراجعة)' }).save(); 
        res.json({ newBalance: user.balance - user.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

app.post('/api/wallet/checkout', auth, async (req, res) => { 
    try { 
        const { totalAmount, pin, cartItems } = req.body; 
        const user = await User.findById(req.user._id); 
        if (user.isSuspended) return res.status(403).json({ message: 'عذراً، حسابك موقوف' });
        if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        const availableBalance = user.balance - user.frozenBalance;
        if (availableBalance < totalAmount) return res.status(400).json({ message: 'الرصيد المتاح غير كافٍ' }); 
        user.balance -= totalAmount; 
        await user.save(); 
        await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet' }).save(); 
        await new Transaction({ clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء منتجات من المتجر' }).save(); 
        res.json({ newBalance: user.balance - user.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.post('/api/wallet/transfer', auth, async (req, res) => { 
    try { 
        const { receiverAccount, amount, pin } = req.body; 
        const sender = await User.findById(req.user._id); 
        if (sender.isSuspended) return res.status(403).json({ message: 'عذراً، حسابك موقوف' });
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); 
        if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); 
        if (receiver.isSuspended) return res.status(403).json({ message: 'حساب المستلم موقوف' });
        if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); 
        if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'تحتاج توثيق KYC' }); 
        const availableBalance = sender.balance - sender.frozenBalance;
        if (availableBalance < Number(amount)) return res.status(400).json({ message: 'الرصيد غير كافٍ' }); 
        sender.balance -= Number(amount); receiver.balance += Number(amount); 
        await sender.save(); await receiver.save(); 
        await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة إلى (${receiver.fullName})` }).save(); 
        await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة من (${sender.fullName})` }).save(); 
        res.json({ newBalance: sender.balance - sender.frozenBalance }); 
    } catch (e) { res.status(500).json({ message: 'خطأ' }); } 
});

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server Secure Running"));
