const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());

// 1. الاتصال بقاعدة البيانات السحابية
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ تم الاتصال بقاعدة بيانات بومة (BOMA) بنجاح!"))
    .catch(err => console.error("❌ خطأ الاتصال:", err));

// 2. النماذج (Schemas)
const UserSchema = new mongoose.Schema({
    fullName: String,
    identity: { type: String, unique: true },
    password: String,
    accountNumber: { type: Number, unique: true },
    balance: { type: Number, default: 50.00 },
    isActive: { type: Boolean, default: false },
    otp: String
});
const User = mongoose.model('User', UserSchema);

const ProductSchema = new mongoose.Schema({
    catIdx: Number,
    arName: String,
    enName: String,
    price: Number,
    img: String,
    arDesc: String,
    enDesc: String
});
const Product = mongoose.model('Product', ProductSchema);

// نموذج طلبات الخدمات (Service Requests)
const RequestSchema = new mongoose.Schema({
    serviceName: String,
    projectName: String,
    description: String,
    clientIdentity: String,
    date: { type: Date, default: Date.now }
});
const ServiceRequest = mongoose.model('ServiceRequest', RequestSchema);

const JWT_SECRET = process.env.JWT_SECRET || "BomaSuperSecretKey2026";

// --- Middleware الحماية ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'غير مصرح لك بالوصول!' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً.' });
        req.user = user;
        next();
    });
};

// --- مسارات المصادقة (Auth) ---
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { fullName, identity, password } = req.body;
        if (!fullName || !identity || !password) return res.status(400).json({ message: 'الرجاء تعبئة جميع الحقول!' });

        const existingUser = await User.findOne({ identity });
        if (existingUser) return res.status(400).json({ message: 'هذا الحساب مسجل بالفعل!' });

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const lastUser = await User.findOne().sort({ accountNumber: -1 });
        const newAccountNumber = lastUser ? lastUser.accountNumber + 1 : 1000000001;
        const generatedOTP = Math.floor(1000 + Math.random() * 9000).toString();

        const newUser = new User({ 
            fullName, 
            identity, 
            password: hashedPassword, 
            accountNumber: newAccountNumber, 
            otp: generatedOTP 
        });
        await newUser.save();

        console.log(`\n📱 [نظام الـ OTP] رمز التحقق لحساب (${identity}) هو: ${generatedOTP}\n`);
        res.status(201).json({ message: 'تم إرسال رمز التحقق بنجاح.', identity, otp: generatedOTP });
    } catch (error) { res.status(500).json({ message: 'خطأ داخلي في الخادم!' }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { identity, otp } = req.body;
        const user = await User.findOne({ identity });
        if (!user) return res.status(404).json({ message: 'الحساب غير موجود!' });
        
        if (user.otp === String(otp)) {
            user.isActive = true; 
            user.otp = null;
            await user.save();
            return res.json({ message: 'تم التفعيل بنجاح!' });
        } else { 
            return res.status(400).json({ message: 'رمز غير صحيح!' }); 
        }
    } catch (error) { res.status(500).json({ message: 'خطأ داخلي!' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identity, password } = req.body;
        const user = await User.findOne({ identity });
        if (!user || !user.isActive) return res.status(400).json({ message: 'البيانات خاطئة أو الحساب غير مفعل!' });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'كلمة المرور غير صحيحة!' });

        const token = jwt.sign({ _id: user._id, accountNumber: user.accountNumber }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ message: 'تم الدخول!', token, user: { name: user.fullName, identity: user.identity, accountNumber: user.accountNumber, balance: user.balance } });
    } catch (error) { res.status(500).json({ message: 'خطأ في السيرفر!' }); }
});

// --- مسارات العمليات المالية (BOMA Pay) ---
app.post('/api/wallet/checkout', authenticateToken, async (req, res) => {
    try {
        const { totalAmount } = req.body;
        const user = await User.findById(req.user._id);
        
        if (!user) return res.status(404).json({ message: 'الحساب غير موجود.' });
        if (user.balance < totalAmount) return res.status(400).json({ message: 'رصيد المحفظة غير كافٍ لإتمام الشراء!' });

        user.balance -= totalAmount;
        await user.save();
        res.json({ message: 'تمت عملية الدفع بنجاح!', newBalance: user.balance });
    } catch (error) { res.status(500).json({ message: 'خطأ في عملية الدفع!' }); }
});

app.post('/api/wallet/transfer', authenticateToken, async (req, res) => {
    try {
        const { receiverAccount, amount } = req.body;
        const transferAmount = Number(amount);
        
        const sender = await User.findById(req.user._id);
        const receiver = await User.findOne({ accountNumber: Number(receiverAccount) });

        if (!sender) return res.status(404).json({ message: 'حسابك غير موجود.' });
        if (!receiver) return res.status(404).json({ message: 'رقم حساب المستلم غير موجود في بومة!' });
        if (sender.accountNumber === receiver.accountNumber) return res.status(400).json({ message: 'لا يمكنك التحويل لنفسك!' });
        if (transferAmount <= 0) return res.status(400).json({ message: 'المبلغ يجب أن يكون أكبر من صفر!' });
        if (sender.balance < transferAmount) return res.status(400).json({ message: 'رصيد محفظتك غير كافٍ!' });

        sender.balance -= transferAmount;
        receiver.balance += transferAmount;

        await sender.save();
        await receiver.save();

        res.json({ message: `تم تحويل $${transferAmount.toFixed(2)} بنجاح إلى ${receiver.fullName}`, newBalance: sender.balance });
    } catch (error) { res.status(500).json({ message: 'خطأ في عملية التحويل!' }); }
});

// --- مسارات المنتجات (Products API) ---
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (error) { res.status(500).json({ message: 'خطأ في جلب المنتجات' }); }
});

app.post('/api/products', async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.status(201).json({ message: 'تم إضافة المنتج بنجاح' });
    } catch (error) { res.status(500).json({ message: 'خطأ في إضافة المنتج' }); }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: 'تم حذف المنتج بنجاح' });
    } catch (error) { res.status(500).json({ message: 'خطأ في الحذف' }); }
});

app.get('/api/products/seed', async (req, res) => {
    try {
        const count = await Product.countDocuments();
        if (count > 0) return res.send('✅ المنتجات موجودة بالفعل في السحابة!');
        
        const seedProducts = [
            { catIdx: 1, arName: "آيفون 15 برو", enName: "iPhone 15 Pro", price: 999, img: "📱", arDesc: "أحدث هاتف من آبل بشريحة A17 Pro.", enDesc: "Latest Apple phone with A17 Pro chip." },
            { catIdx: 2, arName: "نظام إدارة الموارد", enName: "ERP System", price: 1500, img: "💻", arDesc: "نظام سحابي متكامل لإدارة الشركات.", enDesc: "Integrated cloud system for enterprise management." }
        ];
        await Product.insertMany(seedProducts);
        res.send('🚀 تم رفع منتجات بومة إلى قاعدة البيانات السحابية بنجاح!');
    } catch (error) { res.status(500).send('❌ خطأ أثناء رفع المنتجات'); }
});

// --- مسارات طلبات المشاريع والخدمات ---
app.post('/api/requests', async (req, res) => {
    try {
        const { serviceName, projectName, description, clientIdentity } = req.body;
        const newRequest = new ServiceRequest({ serviceName, projectName, description, clientIdentity });
        await newRequest.save();
        res.status(201).json({ message: 'تم استلام الطلب بنجاح!' });
    } catch (error) { 
        res.status(500).json({ message: 'خطأ في حفظ الطلب السحابي' }); 
    }
});

app.get('/api/requests', async (req, res) => {
    try {
        const requests = await ServiceRequest.find().sort({ date: -1 }); // الترتيب من الأحدث للأقدم
        res.json(requests);
    } catch (error) { 
        res.status(500).json({ message: 'خطأ في جلب الطلبات' }); 
    }
});

// --- تشغيل السيرفر ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => { console.log(`🚀 [BOMA Backend v13.0] السيرفر السحابي يعمل بكفاءة على بورت ${PORT}`); });
