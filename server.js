const express = require("express");
const { createClient } = require("@sanity/client");
const app = express();
require("dotenv").config(); // Wczytaj zmienne środowiskowe z pliku .env
const multer = require("multer");
const twilio = require("twilio");
const cors = require("cors");
const session = require("express-session");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

// Konfiguracja
const port = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const OTP_EXPIRY = 10 * 60 * 1000; // 10 minut w milisekundach

// Middleware
app.use(helmet()); // Nagłówki bezpieczeństwa
app.use(express.json());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(session({ 
  secret: SESSION_SECRET, 
  resave: false, 
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// Ograniczenie liczby żądań
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minut
  max: 100,
  message: { error: 'Zbyt wiele żądań, spróbuj ponownie później.' }
});
app.use('/api/', apiLimiter);

const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 godzina
  max: 5,
  message: { error: 'Zbyt wiele żądań OTP, spróbuj ponownie później.' }
});

// Klient Sanity
const sanity = createClient({
  projectId: process.env.SANITY_PROJECT_ID,
  dataset: process.env.SANITY_DATASET,
  useCdn: process.env.NODE_ENV === 'production',
  apiVersion: "2025-03-07",
  token: process.env.SANITY_TOKEN,
});

// Klient Twilio
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// Konfiguracja przesyłania plików
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 10 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'application/msword'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Nieprawidłowy typ pliku. Dozwolone są tylko JPEG, PNG, PDF i DOC.'));
    }
  }
});

// Funkcje walidacyjne
const validatePhone = (phone) => /^\+?\d{7,15}$/.test(phone);

const validateRequest = (req, res, requiredFields) => {
  for (const field of requiredFields) {
    if (!req.body[field]) {
      res.status(400).json({ error: `${field} jest wymagane` });
      return false;
    }
  }
  if (req.body.phone && !validatePhone(req.body.phone)) {
    res.status(400).json({ error: "Nieprawidłowy format numeru telefonu" });
    return false;
  }
  return true;
};

// Obsługa błędów
const errorHandler = (err, req, res, next) => {
  console.error('Błąd:', err.stack);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Plik jest za duży. Maksymalny rozmiar to 5MB.' });
    }
    return res.status(400).json({ error: `Błąd przesyłania pliku: ${err.message}` });
  }
  res.status(500).json({ error: "Błąd wewnętrzny serwera" });
};

// Trasy
app.get("/api/ping", (req, res) => {
  res.json({ message: "Serwer działa! 🚀" });
});

app.post("/api/send-otp", otpLimiter, async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['phone'])) return;
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const existingQuery = `*[_type == "otp" && phone == $phone][0]`;
    const existingOtp = await sanity.fetch(existingQuery, { phone: req.body.phone });
    if (existingOtp) await sanity.delete(existingOtp._id);
    await twilioClient.messages.create({
      body: `Twój kod weryfikacyjny to: ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: req.body.phone
    });
    const doc = {
      _type: "otp",    
      otp,
      phone: req.body.phone,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + OTP_EXPIRY).toISOString()
    };
    const result = await sanity.create(doc);
    setTimeout(async () => {
      try {
        const stillExists = await sanity.fetch(`*[_id == $id][0]._id`, { id: result._id });
        if (stillExists) await sanity.delete(result._id);
      } catch (error) {
        console.error("Nie udało się usunąć OTP:", error.message);
      }
    }, OTP_EXPIRY);
    res.status(200).json({ message: "Kod OTP został wysłany pomyślnie", phone: req.body.phone });
  } catch (error) {
    next(error);
  }
});

// Obsługa błędów
app.use(errorHandler);

// Start serwera
app.listen(port, () => {
  console.log(`Serwer działa na http://localhost:${port}`);
});
