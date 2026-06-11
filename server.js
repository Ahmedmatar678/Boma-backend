const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());

// 1. الاتصال بقاعدة البيانات
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ تم الاتصال بقاعدة بيانات بومة (BOMA) بنجاح!"))
    .catch(err => console.error("❌ خطأ الاتصال:", err));

// 2. النماذج (Schemas)
const UserSchema = new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    termsAccepted: { type: Boolean, required: true }, kycStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    otpAttempts: { type: Number, default: 0 }, accountNumber: { type: Number, unique: true }, balance: { type: Number, default: 50.00 },
    isActive: { type: Boolean, default: false }, otp: String
});
const User = mongoose.model('User', UserSchema);

const ProductSchema = new mongoose.Schema({ catIdx: Number, arName: String, enName: String, price: Number, img: String, arDesc: String, enDesc: String });
const Product = mongoose.model('Product', ProductSchema);

const RequestSchema = new mongoose.Schema({ serviceName: String, projectName: String, description: String, clientIdentity: String, date: { type: Date, default: Date.now } });
const ServiceRequest = mongoose.model('ServiceRequest', RequestSchema);

const BannerSchema = new mongoose.Schema({ placement: { type: String, default: 'carousel' }, arTitle: String, enTitle: String, arDesc: String, enDesc: String, imgUrl: String, date: { type: Date, default: Date.now } });
const Banner = mongoose.model('Banner', BannerSchema);

// النموذج الجديد: صندوق فواتير المبيعات (Orders)
const OrderSchema = new mongoose.Schema({
    clientIdentity: String,
    clientName: String,
    items: Array,
    totalAmount: Number,
    paymentMethod: String,
    status: { type: String, enum: ['pending', 'shipped', 'delivered'], default: 'pending' },
    date: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";

// Middleware الحماية
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'غير مصرح لك بالوصول!' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً.' });
        req.user = user; next();
    });
};

// --- مسارات المصادقة والأمان ---
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { fullName, identity, password, pin, termsAccepted } = req.body;
        if (!fullName || !identity || !password || !pin || !termsAccepted) return res.status(400).json({ message: 'الرجاء تعبئة جميع الحقول والموافقة على الشروط!' });
        const existingUser = await User.findOne({ identity });
        if (existingUser) return res.status(400).json({ message: 'هذا الحساب مسجل بالفعل!' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedPin = await bcrypt.hash(pin, 10);
        const lastUser = await User.findOne().sort({ accountNumber: -1 });
        const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001;
        const generatedOTP = Math.floor(1000 + Math.random() * 9000).toString();
        const newUser = new User({ fullName, identity, password: hashedPassword, pin: hashedPin, termsAccepted, accountNumber: newAccountNumber, otp: generatedOTP });
        await newUser.save();
        res.status(201).json({ message: 'تم إرسال الرمز بنجاح.', identity, otp: generatedOTP });
    } catch (error) { res.status(500).json({ message: 'خطأ داخلي!' }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { identity, otp } = req.body;
        const user = await User.findOne({ identity });
        if (!user) return res.status(404).json({ message: 'الحساب غير موجود!' });
        if (user.otpAttempts >= 3) return res.status(403).json({ message: 'تم حظر الحساب مؤقتاً لتجاوز الحد الأقصى للمحاولات!' });
        if (user.otp === String(otp)) {
            user.isActive = true; user.otp = null; user.otpAttempts = 0; await user.save();
            return res.json({ message: 'تم التفعيل بنجاح!' });
        } else { 
            user.otpAttempts += 1; await user.save();
            return res.status(400).json({ message: `رمز غير صحيح! محاولات متبقية: ${3 - user.otpAttempts}` }); 
        }
    } catch (error) { res.status(500).json({ message: 'خطأ داخلي!' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identity, password } = req.body;
        const user = await User.findOne({ identity });
        if (!user || !user.isActive) return res.status(400).json({ message: 'الحساب غير مفعل أو البيانات خاطئة!' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'كلمة المرور خاطئة!' });
        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance, kycStatus: user.kycStatus } });
    } catch (error) { res.status(500).json({ message: 'خطأ سيرفر!' }); }
});

// --- مسارات العمليات والمبيعات ---

// 1. الدفع عبر المحفظة وتسجيل الفاتورة
app.post('/api/wallet/checkout', authenticateToken, async (req, res) => {
    try {
        const { totalAmount, pin, cartItems } = req.body;
        const user = await User.findById(req.user._id);
        const isPinMatch = await bcrypt.compare(pin, user.pin);
        if (!isPinMatch) return res.status(403).json({ message: 'رمز الـ PIN المالي غير صحيح! العملية ملغاة.' });
        if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيدك غير كافٍ!' });
        
        // خصم الرصيد
        user.balance -= totalAmount; await user.save();

        // تسجيل الفاتورة في قاعدة البيانات
        const newOrder = new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount: totalAmount, paymentMethod: 'BOMA Wallet' });
        await newOrder.save();

        res.json({ newBalance: user.balance, message: 'تم الدفع وتسجيل الطلب بنجاح' });
    } catch (error) { res.status(500).json({ message: 'خطأ مالي!' }); }
});

// 2. تسجيل الفاتورة للعملاء (دفع عند الاستلام أو بطاقة)
app.post('/api/orders', async (req, res) => {
    try {
        const { clientIdentity, clientName, cartItems, totalAmount, paymentMethod } = req.body;
        const newOrder = new Order({ clientIdentity, clientName, items: cartItems, totalAmount, paymentMethod });
        await newOrder.save();
        res.status(201).json({ message: 'تم تسجيل الطلب!' });
    } catch (e) { res.status(500).json(e); }
});

// 3. جلب وتحديث الفواتير (للوحة الإدارة)
app.get('/api/orders', async (req, res) => {
    try { res.json(await Order.find().sort({ date: -1 })); } catch (e) { res.status(500).json(e); }
});
app.put('/api/orders/:id/status', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        res.json(order);
    } catch (e) { res.status(500).json(e); }
});


app.post('/api/wallet/transfer', authenticateToken, async (req, res) => {
    try {
        const { receiverAccount, amount, pin } = req.body;
        const sender = await User.findById(req.user._id);
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) });
        if (!receiver) return res.status(404).json({ message: 'رقم حساب المستلم غير موجود!' });
        const isPinMatch = await bcrypt.compare(pin, sender.pin);
        if (!isPinMatch) return res.status(403).json({ message: 'رمز الـ PIN المالي غير صحيح! تم إيقاف التحويل.' });
        if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).json({ message: 'حسابك غير موثق بالكامل. الحد الأقصى للتحويل هو 100$ فقط!' });
        if (sender.balance < Number(amount)) return res.status(400).json({ message: 'رصيدك غير كافٍ!' });
        sender.balance -= Number(amount); receiver.balance += Number(amount);
        await sender.save(); await receiver.save();
        res.json({ message: 'تم التحويل مالي بنجاح', newBalance: sender.balance });
    } catch (error) { res.status(500).json({ message: 'خطأ تحويل!' }); }
});

app.get('/api/products', async (req, res) => { try { res.json(await Product.find()); } catch (e) { res.status(500).json(e); } });
app.post('/api/products', async (req, res) => { try { const p = new Product(req.body); await p.save(); res.status(201).json(p); } catch (e) { res.status(500).json(e); } });
app.delete('/api/products/:id', async (req, res) => { try { await Product.findByIdAndDelete(req.params.id); res.json({ m: 'deleted' }); } catch (e) { res.status(500).json(e); } });
app.post('/api/requests', async (req, res) => { try { const r = new ServiceRequest(req.body); await r.save(); res.status(201).json(r); } catch (e) { res.status(500).json(e); } });
app.get('/api/requests', async (req, res) => { try { res.json(await ServiceRequest.find().sort({ date: -1 })); } catch (e) { res.status(500).json(e); } });
app.get('/api/banners', async (req, res) => { try { res.json(await Banner.find().sort({ date: -1 })); } catch (e) { res.status(500).json(e); } });
app.post('/api/banners', async (req, res) => { try { const b = new Banner(req.body); await b.save(); res.status(201).json({ message: 'OK' }); } catch (e) { res.status(500).json(e); } });
app.delete('/api/banners/:id', async (req, res) => { try { await Banner.findByIdAndDelete(req.params.id); res.json({ message: 'OK' }); } catch (e) { res.status(500).json(e); } });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => { console.log(`🚀 [BOMA Backend v16.0] يعمل على بورت ${PORT}`); });
