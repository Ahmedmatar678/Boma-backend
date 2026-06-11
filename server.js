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
    .then(() => console.log("✅ سيرفر بومة متصل بالسحابة بنجاح!"))
    .catch(err => console.error("❌ خطأ الاتصال:", err));

// --- النماذج (Schemas) ---
const User = mongoose.model('User', new mongoose.Schema({
    fullName: String, identity: { type: String, unique: true }, password: String, pin: String,
    termsAccepted: Boolean, kycStatus: { type: String, default: 'pending' },
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
    if (!token) return res.status(401).send('غير مصرح');
    jwt.verify(token, JWT_SECRET, (err, user) => { if (err) return res.status(403).send('جلسة منتهية'); req.user = user; next(); });
};

// --- مسارات المصادقة ---
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { fullName, identity, password, pin, termsAccepted } = req.body;
        if (await User.findOne({ identity })) return res.status(400).send('مسجل مسبقاً');
        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedPin = await bcrypt.hash(pin, 10);
        const lastUser = await User.findOne().sort({ accountNumber: -1 });
        const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001;
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        await new User({ fullName, identity, password: hashedPassword, pin: hashedPin, termsAccepted, accountNumber: newAccountNumber, otp }).save();
        res.status(201).json({ identity, otp });
    } catch (e) { res.status(500).send('خطأ'); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    const user = await User.findOne({ identity: req.body.identity });
    if (!user) return res.status(404).send('غير موجود');
    if (user.otpAttempts >= 3) return res.status(403).send('محظور مؤقتاً');
    if (user.otp === String(req.body.otp)) {
        user.isActive = true; user.otp = null; user.otpAttempts = 0; await user.save();
        res.send('تم');
    } else { user.otpAttempts += 1; await user.save(); res.status(400).send('رمز خاطئ'); }
});

app.post('/api/auth/login', async (req, res) => {
    const user = await User.findOne({ identity: req.body.identity });
    if (!user || !user.isActive || !(await bcrypt.compare(req.body.password, user.password))) return res.status(400).send('بيانات خاطئة');
    const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance, kycStatus: user.kycStatus } });
});

// === 🚨 المسارات التي كانت مفقودة (إدارة المستخدمين والـ KYC) 🚨 ===
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('-password -pin').sort({ _id: -1 });
        res.json(users);
    } catch (e) { res.status(500).json(e); }
});

app.put('/api/users/:id/kyc', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { kycStatus: req.body.kycStatus }, { new: true });
        res.json({ message: 'تم تحديث الـ KYC بنجاح', user });
    } catch (e) { res.status(500).json(e); }
});
// ====================================================================

// --- المحفظة والمبيعات ---
app.post('/api/wallet/checkout', auth, async (req, res) => {
    const { totalAmount, pin, cartItems } = req.body;
    const user = await User.findById(req.user._id);
    if (!(await bcrypt.compare(pin, user.pin))) return res.status(403).send('PIN خاطئ');
    if (user.balance < totalAmount) return res.status(400).send('رصيد غير كافٍ');
    user.balance -= totalAmount; await user.save();
    await new Order({ clientIdentity: user.identity, clientName: user.fullName, items: cartItems, totalAmount, paymentMethod: 'BOMA Wallet', status: 'pending' }).save();
    res.json({ newBalance: user.balance });
});

app.post('/api/wallet/transfer', auth, async (req, res) => {
    const { receiverAccount, amount, pin } = req.body;
    const sender = await User.findById(req.user._id);
    const receiver = await User.findOne({ accountNumber: Number(receiverAccount) });
    if (!receiver) return res.status(404).send('حساب غير موجود');
    if (!(await bcrypt.compare(pin, sender.pin))) return res.status(403).send('PIN خاطئ');
    if (sender.kycStatus !== 'approved' && Number(amount) > 100) return res.status(403).send('KYC مطلوب');
    if (sender.balance < Number(amount)) return res.status(400).send('رصيد غير كافٍ');
    sender.balance -= Number(amount); receiver.balance += Number(amount);
    await sender.save(); await receiver.save();
    res.json({ newBalance: sender.balance, message: 'تم التحويل' });
});

app.post('/api/orders', async (req, res) => { try { await new Order(req.body).save(); res.status(201).send('تم الطلب'); } catch(e) { res.status(500).send(e); } });
app.get('/api/orders', async (req, res) => { try { res.json(await Order.find().sort({date:-1})); } catch(e) { res.status(500).send(e); } });
app.put('/api/orders/:id/status', async (req, res) => { try { await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }); res.send('OK'); } catch(e) { res.status(500).send(e); } });

// --- الخدمات والمنتجات والبنرات ---
app.get('/api/products', async (req, res) => { res.json(await Product.find()); });
app.post('/api/products', async (req, res) => { await new Product(req.body).save(); res.status(201).send('OK'); });
app.delete('/api/products/:id', async (req, res) => { await Product.findByIdAndDelete(req.params.id); res.send('OK'); });

app.post('/api/requests', async (req, res) => { await new ServiceRequest(req.body).save(); res.status(201).send('تم'); });
app.get('/api/requests', async (req, res) => { res.json(await ServiceRequest.find().sort({date:-1})); });

app.get('/api/banners', async (req, res) => { res.json(await Banner.find().sort({date:-1})); });
app.post('/api/banners', async (req, res) => { await new Banner(req.body).save(); res.status(201).send('OK'); });
app.delete('/api/banners/:id', async (req, res) => { await Banner.findByIdAndDelete(req.params.id); res.send('OK'); });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA Final Server Running"));
app.delete('/api/products/:id', async (req, res) => { await Product.findByIdAndDelete(req.params.id); res.send('OK'); });

app.post('/api/requests', async (req, res) => { await new ServiceRequest(req.body).save(); res.status(201).send('تم'); });
app.get('/api/requests', async (req, res) => { res.json(await ServiceRequest.find().sort({date:-1})); });

app.get('/api/banners', async (req, res) => { res.json(await Banner.find()); });
app.post('/api/banners', async (req, res) => { await new Banner(req.body).save(); res.status(201).send('OK'); });
app.delete('/api/banners/:id', async (req, res) => { await Banner.findByIdAndDelete(req.params.id); res.send('OK'); });

app.listen(process.env.PORT || 5000, () => console.log("🚀 BOMA v18.0 (With Admin KYC)"));
    } catch (error) { res.status(500).json({ message: 'خطأ مالي!' }); }
});

app.post('/api/orders', async (req, res) => {
    try {
        const { clientIdentity, clientName, cartItems, totalAmount, paymentMethod } = req.body;
        const newOrder = new Order({ clientIdentity, clientName, items: cartItems, totalAmount, paymentMethod });
        await newOrder.save();
        res.status(201).json({ message: 'تم تسجيل الطلب!' });
    } catch (e) { res.status(500).json(e); }
});

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

app.get('/api/products/seed', async (req, res) => {
    try {
        const countP = await Product.countDocuments();
        if (countP === 0) {
            await Product.insertMany([
                { catIdx: 1, arName: "آيفون 15 برو", enName: "iPhone 15 Pro", price: 999, img: "📱", arDesc: "أحدث هاتف من آبل بشريحة A17 Pro.", enDesc: "Latest Apple phone with A17 Pro chip." },
                { catIdx: 2, arName: "نظام إدارة الموارد", enName: "ERP System", price: 1500, img: "💻", arDesc: "نظام سحابي متكامل لإدارة الشركات.", enDesc: "Integrated cloud system for enterprise management." }
            ]);
        }
        const countB = await Banner.countDocuments();
        if (countB === 0) {
            await Banner.insertMany([
                { placement: 'carousel', arTitle: "وسيلة ولا أسهل للدفع", enTitle: "Easiest Payment Method", arDesc: "قسط مع BOMA Pay حتى 24 شهر بدون فوائد 0%", enDesc: "Install with BOMA Pay up to 24 months with 0% interest.", imgUrl: "#ef4444" },
                { placement: 'carousel', arTitle: "أنظمة السحابة البرمجية ERP", enTitle: "ERP Cloud Systems", arDesc: "لوحة تحكم سحابية متكاملة بخصم 30%", enDesc: "Integrated cloud dashboard with 30% off.", imgUrl: "#1e3d59" },
                { placement: 'static', arTitle: "اشترك بخدمات التسويق واستمتع بخصم 50%", enTitle: "Subscribe to Marketing Services with 50% Off", arDesc: "لمدة 3 أشهر على الاشتراكات والأنشطة.", enDesc: "For 3 months on monthly campaigns.", imgUrl: "#1e293b" }
            ]);
        }
        res.send('🚀 تم إعداد قاعدة بيانات بومة بنجاح!');
    } catch (error) { res.status(500).send(error.toString()); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => { console.log(`🚀 [BOMA Backend v17.0] يعمل على بورت ${PORT}`); });
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
