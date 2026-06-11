const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ سيرفر بومة متصل بالسحابة بنجاح!"))
    .catch(err => console.error("❌ خطأ الاتصال:", err));

// 🚀 إعداد خادم البريد الاحترافي (SMTP)
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp-relay.brevo.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false, // Use TLS
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    },
    tls: { rejectUnauthorized: false }
});

// --- النماذج (Schemas) ---
const User = mongoose.model('User', new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    termsAccepted: Boolean, kycStatus: { type: String, default: 'pending' },
    kycDocs: { type: Object, default: {} },
    accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 50 },
    isActive: { type: Boolean, default: false }, otp: String, otpAttempts: { type: Number, default: 0 }
}));
const Product = mongoose.model('Product', new mongoose.Schema({ catIdx: Number, arName: String, enName: String, price: Number, img: String, arDesc: String, enDesc: String }));
const ServiceRequest = mongoose.model('ServiceRequest', new mongoose.Schema({ serviceName: String, projectName: String, description: String, clientIdentity: String, date: { type: Date, default: Date.now } }));
const Banner = mongoose.model('Banner', new mongoose.Schema({ placement: String, arTitle: String, enTitle: String, arDesc: String, enDesc: String, imgUrl: String, date: { type: Date, default: Date.now } }));
const Order = mongoose.model('Order', new mongoose.Schema({ clientIdentity: String, clientName: String, items: Array, totalAmount: Number, paymentMethod: String, status: { type: String, default: 'pending' }, date: { type: Date, default: Date.now } }));
const Notification = mongoose.model('Notification', new mongoose.Schema({ clientIdentity: String, title: String, message: String, isRead: { type: Boolean, default: false }, date: { type: Date, default: Date.now } }));
const Transaction = mongoose.model('Transaction', new mongoose.Schema({ clientIdentity: String, type: String, amount: Number, title: String, date: { type: Date, default: Date.now } }));
const Ticket = mongoose.model('Ticket', new mongoose.Schema({ clientIdentity: String, clientName: String, subject: String, message: String, adminReply: { type: String, default: '' }, status: { type: String, enum: ['pending', 'replied', 'closed'], default: 'pending' }, date: { type: Date, default: Date.now } }));

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";
const auth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'غير مصرح' });
    jwt.verify(token, JWT_SECRET, (err, user) => { 
        if (err) return res.status(403).json({ message: 'جلسة منتهية' }); 
        req.user = user; next(); 
    });
};

// --- المصادقة والـ OTP المحسن ---
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { fullName, identity, password, pin, termsAccepted } = req.body;
        let user = await User.findOne({ identity });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedPin = await bcrypt.hash(pin, 10);
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        const isEmail = identity.includes('@');

        // حل مشكلة (مسجل مسبقاً) للحسابات المعلقة
        if (user) {
            if (user.isActive) return res.status(400).json({ message: 'هذا الحساب مسجل ومفعل مسبقاً' });
            user.fullName = fullName; user.password = hashedPassword; user.pin = hashedPin; user.otp = otp; user.otpAttempts = 0;
        } else {
            const lastUser = await User.findOne().sort({ accountNumber: -1 });
            const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001;
            user = new User({ fullName, identity, password: hashedPassword, pin: hashedPin, termsAccepted, accountNumber: newAccountNumber, otp });
        }
        
        // إرسال الإيميل إذا كان بريداً إلكترونياً
        if (isEmail && process.env.SMTP_USER) {
            try {
                await transporter.sendMail({
                    from: `"BOMA Pay" <${process.env.SMTP_USER}>`,
                    to: identity,
                    subject: 'رمز تفعيل حسابك - BOMA',
                    html: `<div style="text-align:center; font-family:sans-serif; padding:20px; background:#f8fafc; border-radius:10px;">
                            <h2 style="color:#1e3d59;">مرحباً بك في بومة 🦉</h2>
                            <p>رمز التفعيل الخاص بك هو:</p>
                            <h1 style="color:#ff6e40; letter-spacing:5px;">${otp}</h1>
                           </div>`
                });
            } catch (err) { console.error("Mail Error:", err.message); return res.status(500).json({ message: 'خطأ في خادم البريد!' }); }
        }
        
        await user.save();
        // إرسال fallbackOtp لكي يظهر على الشاشة إذا استخدم العميل رقم هاتف
        res.status(201).json({ identity, isEmail, fallbackOtp: isEmail ? null : otp }); 
    } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user) return res.status(404).json({ message: 'غير موجود' });
        if (user.otpAttempts >= 3) return res.status(403).json({ message: 'محظور مؤقتاً بسبب كثرة المحاولات' });
        
        if (user.otp === String(req.body.otp)) {
            if (req.body.purpose === 'forgot') {
                return res.json({ message: 'رمز صحيح' }); 
            } else {
                user.isActive = true; user.otp = null; user.otpAttempts = 0; await user.save();
                await new Notification({ clientIdentity: user.identity, title: 'مرحباً بك في بومة 🎉', message: 'تم تفعيل حسابك المالي بنجاح، ومحفظتك جاهزة.' }).save();
                return res.json({ message: 'تم التفعيل بنجاح' });
            }
        } else { 
            user.otpAttempts += 1; await user.save(); 
            return res.status(400).json({ message: 'رمز خاطئ' }); 
        }
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if(!user || !user.isActive) return res.status(404).json({message: 'الحساب غير موجود أو غير مفعل'});
        
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp; user.otpAttempts = 0; await user.save();
        const isEmail = user.identity.includes('@');
        
        if (isEmail && process.env.SMTP_USER) {
            try {
                await transporter.sendMail({
                    from: `"BOMA Support" <${process.env.SMTP_USER}>`,
                    to: user.identity,
                    subject: 'استعادة كلمة المرور - BOMA',
                    html: `<div style="text-align:center; font-family:sans-serif; padding:20px; background:#f8fafc; border-radius:10px;">
                            <h2 style="color:#1e3d59;">إعادة تعيين كلمة المرور 🔒</h2>
                            <p>طلب استعادة حسابك. رمز التحقق هو:</p>
                            <h1 style="color:#ff6e40; letter-spacing:5px;">${otp}</h1>
                           </div>`
                });
            } catch (err) { return res.status(500).json({ message: 'خطأ في إرسال البريد' }); }
        }
        res.json({ message: 'تم الإرسال', isEmail, fallbackOtp: isEmail ? null : otp });
    } catch(e) { res.status(500).json({message: 'خطأ داخلي'}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { identity, otp, newPassword } = req.body;
        const user = await User.findOne({ identity, otp });
        if(!user) return res.status(400).json({message: 'رمز التحقق غير صالح أو منتهي'});
        
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null; await user.save();
        res.json({message: 'تم تحديث كلمة المرور بنجاح'});
    } catch(e) { res.status(500).json({message: 'خطأ'}); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user) return res.status(400).json({ message: 'البيانات خاطئة أو الحساب غير مسجل' });
        if (!user.isActive) return res.status(400).json({ message: 'الحساب غير مفعل، قم بالتسجيل مجدداً لتفعيله' });
        if (!(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'كلمة المرور خاطئة' });
        
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance, kycStatus: user.kycStatus } });
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

// --- الدعم الفني ---
app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/support', async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد من الدعم الفني 🎧', message: `تم الرد على تذكرتك. يرجى مراجعة قسم الدعم.` }).save(); res.json({ message: 'تم', ticket }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- إدارة التوثيق (KYC) ---
app.get('/api/users', async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', async (req, res) => { try { const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true }); const text = req.body.kycStatus === 'approved' ? 'تهانينا! تم قبول مستنداتك وتوثيق حسابك. ✨' : 'تم رفض مستندات التوثيق، يرجى إعادة الرفع.'; await new Notification({ clientIdentity: user.identity, title: 'تحديث حالة التوثيق 🛡️', message: text }).save(); res.json({ message: 'تم', user }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); await new Notification({ clientIdentity: user.identity, title: 'المستندات قيد المراجعة ⏳', message: 'تم استلام المستندات وهي تحت المراجعة.' }).save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// --- التنبيهات والسجل المالي ---
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/transactions', async (req, res) => { try { res.json(await Transaction.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المحفظة والمبيعات ---
app.post('/api/wallet/checkout', auth, async (req, res) => { try { const { totalAmount, pin, cartItems } = req.body; const user = await User.findById(req.user._id); if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيد غير كافٍ' }); user.balance -= totalAmount; await user.save(); await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet' }).save(); await new Notification({ clientIdentity: user.identity, title: 'عملية شراء ناجحة 🛒', message: `تم خصم $${totalAmount.toFixed(2)} مقابل طلبات المتجر.` }).save(); await new Transaction({ clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء منتجات من المتجر' }).save(); res.json({ newBalance: user.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/transfer', auth, async (req, res) => { try { const { receiverAccount, amount, pin } = req.body; const sender = await User.findById(req.user._id); const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'تحتاج توثيق KYC' }); if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيد غير كافٍ' }); sender.balance -= Number(amount); receiver.balance += Number(amount); await sender.save(); await receiver.save(); await new Notification({ clientIdentity: sender.identity, title: 'حوالة صادرة 💸', message: `تم تحويل $${Number(amount).toFixed(2)} لحساب ${receiver.fullName}.` }).save(); await new Notification({ clientIdentity: receiver.identity, title: 'حوالة واردة 💰', message: `استلمت $${Number(amount).toFixed(2)} من ${sender.fullName}.` }).save(); await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة إلى (${receiver.fullName})` }).save(); await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة من (${sender.fullName})` }).save(); res.json({ newBalance: sender.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); await new Notification({ clientIdentity: req.body.clientIdentity, title: 'طلب جديد 📦', message: `تم تسجيل طلبك بقيمة $${req.body.totalAmount}.` }).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', async (req, res) => { try { const o = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); const t = req.body.status === 'shipped' ? '🚚 تم الشحن' : '✅ تم التسليم'; await new Notification({ clientIdentity: o.clientIdentity, title: 'تحديث الشحن', message: t }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المنتجات والخدمات ---
app.get('/api/products', async (req, res) => { try{ res.json(await Product.find()); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/products', async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/products/:id', async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/requests', async (req, res) => { try{ await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/requests', async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/banners', async (req, res) => { try{ res.json(await Banner.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server v26.0 (Perfect OTP & Error Handling)"));
        user.otp = otp; user.otpAttempts = 0; await user.save();
        
        if (user.identity.includes('@') && process.env.SMTP_USER) {
            await transporter.sendMail({
                from: `"BOMA Support" <${process.env.EMAIL_FROM || process.env.SMTP_USER}>`,
                to: user.identity,
                subject: 'استعادة كلمة المرور - BOMA',
                html: `<div style="text-align:center; font-family:sans-serif; padding:20px; background:#f8fafc; border-radius:10px;">
                        <h2 style="color:#1e3d59;">إعادة تعيين كلمة المرور 🔒</h2>
                        <p>طلب استعادة حسابك. رمز التحقق هو:</p>
                        <h1 style="color:#ff6e40; letter-spacing:5px; background:#fff; padding:10px; border-radius:8px; display:inline-block;">${otp}</h1>
                       </div>`
            });
        }
        res.json({ message: 'تم إرسال الرمز' });
    } catch(e) { res.status(500).json({message: 'خطأ داخلي'}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { identity, otp, newPassword } = req.body;
        const user = await User.findOne({ identity, otp });
        if(!user) return res.status(400).json({message: 'رمز التحقق غير صالح أو منتهي'});
        
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null; await user.save();
        res.json({message: 'تم تحديث كلمة المرور بنجاح'});
    } catch(e) { res.status(500).json({message: 'خطأ'}); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user || !user.isActive || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'بيانات خاطئة' });
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance, kycStatus: user.kycStatus } });
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

// --- الدعم الفني ---
app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/support', async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد من الدعم الفني 🎧', message: `تم الرد على تذكرتك. يرجى مراجعة قسم الدعم.` }).save(); res.json({ message: 'تم', ticket }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- إدارة التوثيق (KYC) ---
app.get('/api/users', async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', async (req, res) => { try { const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true }); const text = req.body.kycStatus === 'approved' ? 'تهانينا! تم قبول مستنداتك وتوثيق حسابك. ✨' : 'تم رفض مستندات التوثيق، يرجى إعادة الرفع.'; await new Notification({ clientIdentity: user.identity, title: 'تحديث حالة التوثيق 🛡️', message: text }).save(); res.json({ message: 'تم', user }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); await new Notification({ clientIdentity: user.identity, title: 'المستندات قيد المراجعة ⏳', message: 'تم استلام المستندات وهي تحت المراجعة.' }).save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// --- التنبيهات والسجل المالي ---
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/transactions', async (req, res) => { try { res.json(await Transaction.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المحفظة والمبيعات ---
app.post('/api/wallet/checkout', auth, async (req, res) => { try { const { totalAmount, pin, cartItems } = req.body; const user = await User.findById(req.user._id); if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيد غير كافٍ' }); user.balance -= totalAmount; await user.save(); await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet' }).save(); await new Notification({ clientIdentity: user.identity, title: 'عملية شراء ناجحة 🛒', message: `تم خصم $${totalAmount.toFixed(2)} مقابل طلبات المتجر.` }).save(); await new Transaction({ clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء منتجات من المتجر' }).save(); res.json({ newBalance: user.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/transfer', auth, async (req, res) => { try { const { receiverAccount, amount, pin } = req.body; const sender = await User.findById(req.user._id); const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'تحتاج توثيق KYC' }); if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيد غير كافٍ' }); sender.balance -= Number(amount); receiver.balance += Number(amount); await sender.save(); await receiver.save(); await new Notification({ clientIdentity: sender.identity, title: 'حوالة صادرة 💸', message: `تم تحويل $${Number(amount).toFixed(2)} لحساب ${receiver.fullName}.` }).save(); await new Notification({ clientIdentity: receiver.identity, title: 'حوالة واردة 💰', message: `استلمت $${Number(amount).toFixed(2)} من ${sender.fullName}.` }).save(); await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة إلى (${receiver.fullName})` }).save(); await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة من (${sender.fullName})` }).save(); res.json({ newBalance: sender.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); await new Notification({ clientIdentity: req.body.clientIdentity, title: 'طلب جديد 📦', message: `تم تسجيل طلبك بقيمة $${req.body.totalAmount}.` }).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', async (req, res) => { try { const o = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); const t = req.body.status === 'shipped' ? '🚚 تم الشحن' : '✅ تم التسليم'; await new Notification({ clientIdentity: o.clientIdentity, title: 'تحديث الشحن', message: t }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المنتجات والخدمات ---
app.get('/api/products', async (req, res) => { try{ res.json(await Product.find()); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/products', async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/products/:id', async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/requests', async (req, res) => { try{ await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/requests', async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/banners', async (req, res) => { try{ res.json(await Banner.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server v24.0 (Real SMTP OTP Active)"));

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { identity, otp, purpose } = req.body;
        const user = await User.findOne({ identity });
        if (!user) return res.status(404).json({ message: 'الحساب غير موجود' });
        if (user.otpAttempts >= 5) return res.status(403).json({ message: 'تم حظر الحساب مؤقتاً لكثرة المحاولات الخاطئة' });
        
        if (user.otp === String(otp)) {
            if (purpose === 'forgot') {
                return res.json({ message: 'رمز صحيح' }); 
            } else {
                user.isActive = true; user.otp = null; user.otpAttempts = 0; await user.save();
                await new Notification({ clientIdentity: user.identity, title: 'مرحباً بك في بومة 🎉', message: 'تم تفعيل حسابك المالي بنجاح، ومحفظتك جاهزة.' }).save();
                return res.json({ message: 'تم التفعيل بنجاح' });
            }
        } else { 
            user.otpAttempts += 1; await user.save(); 
            return res.status(400).json({ message: 'رمز الـ OTP غير صحيح' }); 
        }
    } catch (e) { return res.status(500).json({ message: 'خطأ أثناء معالجة الرمز' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { identity } = req.body;
        const user = await User.findOne({ identity });
        if(!user) return res.status(404).json({message: 'هذا الحساب غير مسجل لدينا'});
        if(!user.isActive) return res.status(400).json({message: 'هذا الحساب معلق ولم يتم تفعيله بالـ OTP بعد'});
        
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        
        if (identity.includes('@') && process.env.SMTP_USER) {
            try {
                await transporter.sendMail({
                    from: `"BOMA Support" <${process.env.SMTP_USER}>`,
                    to: identity,
                    subject: 'استعادة كلمة المرور - BOMA',
                    html: `<div style="text-align:center; font-family:sans-serif; padding:20px; background:#f8fafc; border-radius:10px;">
                            <h2 style="color:#1e3d59;">إعادة تعيين كلمة المرور 🔒</h2>
                            <p>طلب استعادة حسابك. رمز التحقق هو:</p>
                            <h1 style="color:#ff6e40; letter-spacing:5px; background:#fff; padding:10px; border-radius:8px; display:inline-block;">${otp}</h1>
                           </div>`
                });
            } catch (mailErr) {
                console.error("❌ خطأ بريد الاستعادة:", mailErr.message);
                return res.status(500).json({ message: `فشل إرسال بريد الاستعادة: ${mailErr.message}` });
            }
        }
        
        user.otp = otp; user.otpAttempts = 0; await user.save();
        return res.json({ message: 'تم إرسال الرمز' });
    } catch(e) { return res.status(500).json({message: 'خطأ داخلي'}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { identity, otp, newPassword } = req.body;
        const user = await User.findOne({ identity, otp });
        if(!user) return res.status(400).json({message: 'رمز التحقق غير صحيح أو منتهي الصلاحية'});
        
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null; await user.save();
        return res.json({message: 'تم تحديث كلمة المرور بنجاح'});
    } catch(e) { return res.status(500).json({message: 'خطأ في التحديث'}); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user) return res.status(400).json({ message: 'هذا الحساب غير مسجل لدينا' });
        if (!user.isActive) return res.status(400).json({ message: 'الحساب غير مفعل، يرجى التسجيل مجدداً لتلقي رمز OTP' });
        if (!(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'كلمة المرور المدخلة خاطئة' });
        
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance, kycStatus: user.kycStatus } });
    } catch (e) { return res.status(500).json({ message: 'خطأ في الخادم' }); }
});

// --- الدعم الفني ---
app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/support', async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد من الدعم الفني 🎧', message: `تم الرد على تذكرتك. يرجى مراجعة قسم الدعم.` }).save(); res.json({ message: 'تم', ticket }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- إدارة التوثيق (KYC) ---
app.get('/api/users', async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', async (req, res) => { try { const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true }); const text = req.body.kycStatus === 'approved' ? 'تهانينا! تم قبول مستنداتك وتوثيق حسابك. ✨' : 'تم رفض مستندات التوثيق، يرجى إعادة الرفع.'; await new Notification({ clientIdentity: user.identity, title: 'تحديث حالة التوثيق 🛡️', message: text }).save(); res.json({ message: 'تم', user }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); await new Notification({ clientIdentity: user.identity, title: 'المستندات قيد المراجعة ⏳', message: 'تم استلام المستندات وهي تحت المراجعة.' }).save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// --- التنبيهات والسجل المالي ---
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/transactions', async (req, res) => { try { res.json(await Transaction.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المحفظة والمبيعات ---
app.post('/api/wallet/checkout', auth, async (req, res) => { try { const { totalAmount, pin, cartItems } = req.body; const user = await User.findById(req.user._id); if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيد غير كافٍ' }); user.balance -= totalAmount; await user.save(); await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet' }).save(); await new Notification({ clientIdentity: user.identity, title: 'عملية شراء ناجحة 🛒', message: `تم خصم $${totalAmount.toFixed(2)} مقابل طلبات المتجر.` }).save(); await new Transaction({ clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء منتجات من المتجر' }).save(); res.json({ newBalance: user.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/transfer', auth, async (req, res) => { try { const { receiverAccount, amount, pin } = req.body; const sender = await User.findById(req.user._id); const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'تحتاج توثيق KYC' }); if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيد غير كافٍ' }); sender.balance -= Number(amount); receiver.balance += Number(amount); await sender.save(); await receiver.save(); await new Notification({ clientIdentity: sender.identity, title: 'حوالة صادرة 💸', message: `تم تحويل $${Number(amount).toFixed(2)} لحساب ${receiver.fullName}.` }).save(); await new Notification({ clientIdentity: receiver.identity, title: 'حوالة واردة 💰', message: `استلمت $${Number(amount).toFixed(2)} من ${sender.fullName}.` }).save(); await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة إلى (${receiver.fullName})` }).save(); await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة من (${sender.fullName})` }).save(); res.json({ newBalance: sender.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); await new Notification({ clientIdentity: req.body.clientIdentity, title: 'طلب جديد 📦', message: `تم تسجيل طلبك بقيمة $${req.body.totalAmount}.` }).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', async (req, res) => { try { const o = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); const t = req.body.status === 'shipped' ? '🚚 تم الشحن' : '✅ تم التسليم'; await new Notification({ clientIdentity: o.clientIdentity, title: 'تحديث الشحن', message: t }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المنتجات والخدمات ---
app.get('/api/products', async (req, res) => { try{ res.json(await Product.find()); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/products', async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/products/:id', async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/requests', async (req, res) => { try{ await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/requests', async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/banners', async (req, res) => { try{ res.json(await Banner.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server v25.0 Running with Bulletproof Auth Logics"));
            } else {
                user.isActive = true; user.otp = null; user.otpAttempts = 0; await user.save();
                await new Notification({ clientIdentity: user.identity, title: 'مرحباً بك في بومة 🎉', message: 'تم تفعيل حسابك المالي بنجاح، ومحفظتك جاهزة.' }).save();
                return res.json({ message: 'تم التفعيل بنجاح' });
            }
        } else { 
            user.otpAttempts += 1; await user.save(); 
            return res.status(400).json({ message: 'رمز الـ OTP خاطئ' }); 
        }
    } catch (e) { res.status(500).json({ message: 'خطأ في التحقق' }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        // 🚀 حل مشكلة محاولة الاستعادة لحساب غير مفعل
        if(!user || !user.isActive) return res.status(404).json({message: 'هذا الحساب غير موجود أو غير مفعل'});
        
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        
        if (user.identity.includes('@') && process.env.SMTP_USER) {
            try {
                await transporter.sendMail({
                    from: `"BOMA Support" <${process.env.SMTP_USER}>`,
                    to: user.identity,
                    subject: 'استعادة كلمة المرور - BOMA',
                    html: `<div style="text-align:center; font-family:sans-serif; padding:20px; background:#f8fafc; border-radius:10px;">
                            <h2 style="color:#1e3d59;">إعادة تعيين كلمة المرور 🔒</h2>
                            <p>طلب استعادة حسابك. رمز التحقق هو:</p>
                            <h1 style="color:#ff6e40; letter-spacing:5px; background:#fff; padding:10px; border-radius:8px; display:inline-block;">${otp}</h1>
                           </div>`
                });
            } catch (mailErr) {
                console.error("Mail Error:", mailErr);
                return res.status(500).json({ message: 'فشل إرسال الإيميل! تأكد من إعدادات السيرفر.' });
            }
        }
        
        user.otp = otp; user.otpAttempts = 0; await user.save();
        res.json({ message: 'تم إرسال الرمز' });
    } catch(e) { res.status(500).json({message: 'خطأ داخلي'}); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { identity, otp, newPassword } = req.body;
        const user = await User.findOne({ identity, otp });
        if(!user) return res.status(400).json({message: 'رمز التحقق غير صالح أو منتهي'});
        
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null; await user.save();
        res.json({message: 'تم تحديث كلمة المرور بنجاح'});
    } catch(e) { res.status(500).json({message: 'خطأ في التحديث'}); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user || !user.isActive || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'بيانات خاطئة' });
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance, kycStatus: user.kycStatus } });
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

// --- الدعم الفني ---
app.post('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await new Ticket({ clientIdentity: user.identity, clientName: user.fullName, subject: req.body.subject, message: req.body.message }).save(); res.json({ message: 'تم الإرسال' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/support', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Ticket.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/admin/support', async (req, res) => { try { res.json(await Ticket.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/admin/support/:id', async (req, res) => { try { const ticket = await Ticket.findByIdAndUpdate(req.params.id, { adminReply: req.body.reply, status: 'replied' }, { new: true }); await new Notification({ clientIdentity: ticket.clientIdentity, title: 'رد من الدعم الفني 🎧', message: `تم الرد على تذكرتك. يرجى مراجعة قسم الدعم.` }).save(); res.json({ message: 'تم', ticket }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- إدارة التوثيق (KYC) ---
app.get('/api/users', async (req, res) => { try { res.json(await User.find().select('-password -pin').sort({ _id: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/users/:id/kyc', async (req, res) => { try { const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true }); const text = req.body.kycStatus === 'approved' ? 'تهانينا! تم قبول مستنداتك وتوثيق حسابك. ✨' : 'تم رفض مستندات التوثيق، يرجى إعادة الرفع.'; await new Notification({ clientIdentity: user.identity, title: 'تحديث حالة التوثيق 🛡️', message: text }).save(); res.json({ message: 'تم', user }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/submit-kyc', auth, async (req, res) => { try { const user = await User.findById(req.user._id); user.kycDocs = { docType: req.body.docType, docImage: req.body.docImage, selfieImage: req.body.selfieImage }; user.kycStatus = 'pending'; await user.save(); await new Notification({ clientIdentity: user.identity, title: 'المستندات قيد المراجعة ⏳', message: 'تم استلام المستندات وهي تحت المراجعة.' }).save(); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });

// --- التنبيهات والسجل المالي ---
app.get('/api/notifications', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/notifications/read', auth, async (req, res) => { try { const user = await User.findById(req.user._id); await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true }); res.json({ message: 'تم' }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/wallet/transactions', auth, async (req, res) => { try { const user = await User.findById(req.user._id); res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 })); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/transactions', async (req, res) => { try { res.json(await Transaction.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المحفظة والمبيعات ---
app.post('/api/wallet/checkout', auth, async (req, res) => { try { const { totalAmount, pin, cartItems } = req.body; const user = await User.findById(req.user._id); if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيد غير كافٍ' }); user.balance -= totalAmount; await user.save(); await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet' }).save(); await new Notification({ clientIdentity: user.identity, title: 'عملية شراء ناجحة 🛒', message: `تم خصم $${totalAmount.toFixed(2)} مقابل طلبات المتجر.` }).save(); await new Transaction({ clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء منتجات من المتجر' }).save(); res.json({ newBalance: user.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/wallet/transfer', auth, async (req, res) => { try { const { receiverAccount, amount, pin } = req.body; const sender = await User.findById(req.user._id); const receiver = await User.findOne({ accountNumber: Number(receiverAccount) }); if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' }); if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' }); if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'تحتاج توثيق KYC' }); if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيد غير كافٍ' }); sender.balance -= Number(amount); receiver.balance += Number(amount); await sender.save(); await receiver.save(); await new Notification({ clientIdentity: sender.identity, title: 'حوالة صادرة 💸', message: `تم تحويل $${Number(amount).toFixed(2)} لحساب ${receiver.fullName}.` }).save(); await new Notification({ clientIdentity: receiver.identity, title: 'حوالة واردة 💰', message: `استلمت $${Number(amount).toFixed(2)} من ${sender.fullName}.` }).save(); await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة إلى (${receiver.fullName})` }).save(); await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة من (${sender.fullName})` }).save(); res.json({ newBalance: sender.balance }); } catch (e) { res.status(500).json({ message: 'خطأ' }); } });
app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); await new Notification({ clientIdentity: req.body.clientIdentity, title: 'طلب جديد 📦', message: `تم تسجيل طلبك بقيمة $${req.body.totalAmount}.` }).save(); res.status(201).json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', async (req, res) => { try { const o = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); const t = req.body.status === 'shipped' ? '🚚 تم الشحن' : '✅ تم التسليم'; await new Notification({ clientIdentity: o.clientIdentity, title: 'تحديث الشحن', message: t }).save(); res.json({ message: 'تم' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المنتجات والخدمات ---
app.get('/api/products', async (req, res) => { try{ res.json(await Product.find()); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/products', async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/products/:id', async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/requests', async (req, res) => { try{ await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/requests', async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/banners', async (req, res) => { try{ res.json(await Banner.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server v25.0 (Authentication Fixed)"));

// --- التنبيهات والسجل المالي ---
app.get('/api/notifications', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json(await Notification.find({ clientIdentity: user.identity }).sort({ date: -1 }));
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

app.put('/api/notifications/read', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        await Notification.updateMany({ clientIdentity: user.identity, isRead: false }, { isRead: true });
        res.json({ message: 'تم' });
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

// 🚀 مسارات جلب السجل المالي (كانت مفقودة)
app.get('/api/wallet/transactions', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json(await Transaction.find({ clientIdentity: user.identity }).sort({ date: -1 }));
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

app.get('/api/transactions', async (req, res) => {
    try { res.json(await Transaction.find().sort({ date: -1 })); } catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

// --- المحفظة والمبيعات (مع تسجيل العمليات) ---
app.post('/api/wallet/checkout', auth, async (req, res) => {
    try {
        const { totalAmount, pin, cartItems } = req.body;
        const user = await User.findById(req.user._id);
        if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' });
        if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيد غير كافٍ' });
        
        user.balance -= totalAmount; await user.save();
        await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet' }).save();
        await new Notification({ clientIdentity: user.identity, title: 'عملية شراء ناجحة 🛒', message: `تم خصم $${totalAmount.toFixed(2)} مقابل طلبات المتجر.` }).save();
        
        // 🚀 تسجيل العملية في السجل المالي
        await new Transaction({ clientIdentity: user.identity, type: 'out', amount: totalAmount, title: 'شراء منتجات من المتجر' }).save();

        res.json({ newBalance: user.balance });
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

app.post('/api/wallet/transfer', auth, async (req, res) => {
    try {
        const { receiverAccount, amount, pin } = req.body;
        const sender = await User.findById(req.user._id);
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) });
        if (!receiver) return res.status(404).json({ message: 'المستلم غير موجود' });
        if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' });
        if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'تحتاج توثيق KYC' });
        if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيد غير كافٍ' });

        sender.balance -= Number(amount); receiver.balance += Number(amount);
        await sender.save(); await receiver.save();

        await new Notification({ clientIdentity: sender.identity, title: 'حوالة صادرة 💸', message: `تم تحويل $${Number(amount).toFixed(2)} لحساب ${receiver.fullName}.` }).save();
        await new Notification({ clientIdentity: receiver.identity, title: 'حوالة واردة 💰', message: `استلمت $${Number(amount).toFixed(2)} من ${sender.fullName}.` }).save();

        // 🚀 تسجيل العملية في السجل المالي للطرفين
        await new Transaction({ clientIdentity: sender.identity, type: 'out', amount: Number(amount), title: `حوالة مالية إلى (${receiver.fullName})` }).save();
        await new Transaction({ clientIdentity: receiver.identity, type: 'in', amount: Number(amount), title: `حوالة واردة من (${sender.fullName})` }).save();

        res.json({ newBalance: sender.balance });
    } catch (e) { res.status(500).json({ message: 'خطأ' }); }
});

// --- الطلبات المتنوعة ---
app.post('/api/orders', async (req, res) => { 
    try { await new Order(req.body).save(); await new Notification({ clientIdentity: req.body.clientIdentity, title: 'طلب جديد 📦', message: `تم تسجيل طلبك بقيمة $${req.body.totalAmount}.` }).save(); res.status(201).json({ message: 'تم' }); } 
    catch(e) { res.status(500).json({ message: 'خطأ' }); } 
});
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', async (req, res) => {
    try { const o = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true }); const t = req.body.status === 'shipped' ? '🚚 تم الشحن' : '✅ تم التسليم'; await new Notification({ clientIdentity: o.clientIdentity, title: 'تحديث الشحن', message: t }).save(); res.json({ message: 'تم' }); } 
    catch(e) { res.status(500).json({ message: 'خطأ' }); }
});

app.get('/api/products', async (req, res) => { try{ res.json(await Product.find()); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/products', async (req, res) => { try{ await new Product(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/products/:id', async (req, res) => { try{ await Product.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.post('/api/requests', async (req, res) => { try{ await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.get('/api/requests', async (req, res) => { try{ res.json(await ServiceRequest.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.get('/api/banners', async (req, res) => { try{ res.json(await Banner.find().sort({date:-1})); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.post('/api/banners', async (req, res) => { try{ await new Banner(req.body).save(); res.status(201).json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });
app.delete('/api/banners/:id', async (req, res) => { try{ await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'تم' }); } catch(e){ res.status(500).json({message:'خطأ'}); } });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server v21.0 (Ledger Fixed) Running"));
