const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
// زيادة مساحة الاستقبال لضمان وصول الصور المرفوعة (Base64)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ سيرفر بومة متصل بالسحابة بنجاح!"))
    .catch(err => console.error("❌ خطأ الاتصال:", err));

// النماذج (Schemas)
const User = mongoose.model('User', new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    termsAccepted: Boolean, kycStatus: { type: String, default: 'pending' },
    // إضافة حقل مستندات التوثيق
    kycDocs: { docType: String, docImage: String, selfieImage: String },
    accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 50 },
    isActive: { type: Boolean, default: false }, otp: String, otpAttempts: { type: Number, default: 0 }
}));

const Product = mongoose.model('Product', new mongoose.Schema({ catIdx: Number, arName: String, enName: String, price: Number, img: String, arDesc: String, enDesc: String }));
const ServiceRequest = mongoose.model('ServiceRequest', new mongoose.Schema({ serviceName: String, projectName: String, description: String, clientIdentity: String, date: { type: Date, default: Date.now } }));
const Banner = mongoose.model('Banner', new mongoose.Schema({ placement: String, arTitle: String, enTitle: String, arDesc: String, enDesc: String, imgUrl: String, date: { type: Date, default: Date.now } }));
const Order = mongoose.model('Order', new mongoose.Schema({ clientIdentity: String, clientName: String, items: Array, totalAmount: Number, paymentMethod: String, status: { type: String, default: 'pending' }, date: { type: Date, default: Date.now } }));

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";
const auth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'غير مصرح' });
    jwt.verify(token, JWT_SECRET, (err, user) => { 
        if (err) return res.status(403).json({ message: 'جلسة منتهية' }); 
        req.user = user; next(); 
    });
};

// --- مسارات المصادقة ---
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { fullName, identity, password, pin, termsAccepted } = req.body;
        if (await User.findOne({ identity })) return res.status(400).json({ message: 'مسجل مسبقاً' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedPin = await bcrypt.hash(pin, 10);
        const lastUser = await User.findOne().sort({ accountNumber: -1 });
        const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001;
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        await new User({ fullName, identity, password: hashedPassword, pin: hashedPin, termsAccepted, accountNumber: newAccountNumber, otp }).save();
        res.status(201).json({ identity, otp });
    } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user) return res.status(404).json({ message: 'غير موجود' });
        if (user.otpAttempts >= 3) return res.status(403).json({ message: 'محظور مؤقتاً' });
        if (user.otp === String(req.body.otp)) {
            user.isActive = true; user.otp = null; user.otpAttempts = 0; await user.save();
            res.json({ message: 'تم التفعيل بنجاح' });
        } else { 
            user.otpAttempts += 1; await user.save(); 
            res.status(400).json({ message: 'رمز خاطئ' }); 
        }
    } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ identity: req.body.identity });
        if (!user || !user.isActive || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).json({ message: 'بيانات خاطئة' });
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance, kycStatus: user.kycStatus } });
    } catch (e) { res.status(500).json({ message: 'خطأ داخلي' }); }
});

// --- إدارة المستخدمين (KYC) ---
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('-password -pin').sort({ _id: -1 });
        res.json(users);
    } catch (e) { res.status(500).json({ message: 'خطأ جلب' }); }
});

app.put('/api/users/:id/kyc', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true });
        res.json({ message: 'تم تحديث الـ KYC بنجاح', user });
    } catch (e) { res.status(500).json({ message: 'خطأ تحديث' }); }
});

// === المسار الجديد: رفع مستندات التوثيق من التطبيق ===
app.post('/api/wallet/submit-kyc', auth, async (req, res) => {
    try {
        const { docType, docImage, selfieImage } = req.body;
        const user = await User.findById(req.user._id);
        user.kycDocs = { docType, docImage, selfieImage };
        user.kycStatus = 'pending';
        await user.save();
        res.json({ message: 'تم استلام مستنداتك بنجاح، جاري المراجعة.' });
    } catch (e) { res.status(500).json({ message: 'خطأ في رفع المستندات' }); }
});
// =======================================================

// --- المحفظة والمبيعات ---
app.post('/api/wallet/checkout', auth, async (req, res) => {
    try {
        const { totalAmount, pin, cartItems } = req.body;
        const user = await User.findById(req.user._id);
        if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).json({ message: 'PIN خاطئ' });
        if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيد غير كافٍ' });
        user.balance -= totalAmount; await user.save();
        await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet', status: 'pending' }).save();
        res.json({ newBalance: user.balance, message: 'تم الخصم بنجاح' });
    } catch (e) { res.status(500).json({ message: 'خطأ مالي' }); }
});

app.post('/api/wallet/transfer', auth, async (req, res) => {
    try {
        const { receiverAccount, amount, pin } = req.body;
        const sender = await User.findById(req.user._id);
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) });
        if (!receiver) return res.status(404).json({ message: 'حساب المستلم غير موجود' });
        if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).json({ message: 'PIN خاطئ' });
        if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'KYC مطلوب للتحويلات الكبيرة' });
        if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيد غير كافٍ' });
        sender.balance -= Number(amount); receiver.balance += Number(amount);
        await sender.save(); await receiver.save();
        res.json({ newBalance: sender.balance, message: 'تم التحويل' });
    } catch (e) { res.status(500).json({ message: 'خطأ مالي' }); }
});

app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); res.status(201).json({ message: 'تم الطلب' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }); res.json({ message: 'OK' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المنتجات والخدمات واللوحات ---
app.get('/api/products', async (req, res) => { res.json(await Product.find()); });
app.post('/api/products', async (req, res) => { await new Product(req.body).save(); res.status(201).json({ message: 'OK' }); });
app.delete('/api/products/:id', async (req, res) => { await Product.findByIdAndDelete(req.params.id); res.json({ message: 'OK' }); });

app.post('/api/requests', async (req, res) => { await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); });
app.get('/api/requests', async (req, res) => { res.json(await ServiceRequest.find().sort({date:-1})); });

app.get('/api/banners', async (req, res) => { res.json(await Banner.find().sort({date:-1})); });
app.post('/api/banners', async (req, res) => { await new Banner(req.body).save(); res.status(201).json({ message: 'OK' }); });
app.delete('/api/banners/:id', async (req, res) => { await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'OK' }); });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Server v18.0 (With Full KYC) Running"));
        if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'KYC مطلوب' });
        if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيد غير كافٍ' });
        sender.balance -= Number(amount); receiver.balance += Number(amount);
        await sender.save(); await receiver.save();
        res.json({ newBalance: sender.balance, message: 'تم التحويل' });
    } catch (e) { res.status(500).json({ message: 'خطأ مالي' }); }
});

app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); res.status(201).json({ message: 'تم الطلب' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });
app.put('/api/orders/:id/status', async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }); res.json({ message: 'OK' }); } catch(e) { res.status(500).json({ message: 'خطأ' }); } });

// --- المنتجات والخدمات واللوحات ---
app.get('/api/products', async (req, res) => { res.json(await Product.find()); });
app.post('/api/products', async (req, res) => { await new Product(req.body).save(); res.status(201).json({ message: 'OK' }); });
app.delete('/api/products/:id', async (req, res) => { await Product.findByIdAndDelete(req.params.id); res.json({ message: 'OK' }); });

app.post('/api/requests', async (req, res) => { await new ServiceRequest(req.body).save(); res.status(201).json({ message: 'تم' }); });
app.get('/api/requests', async (req, res) => { res.json(await ServiceRequest.find().sort({date:-1})); });

app.get('/api/banners', async (req, res) => { res.json(await Banner.find().sort({date:-1})); });
app.post('/api/banners', async (req, res) => { await new Banner(req.body).save(); res.status(201).json({ message: 'OK' }); });
app.delete('/api/banners/:id', async (req, res) => { await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'OK' }); });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Final Server Running"));
