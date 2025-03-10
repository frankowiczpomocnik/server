const express = require("express");
const { createClient } = require("@sanity/client");
const app = express();
require("dotenv").config(); // Load environment variables from .env file
const multer = require("multer");
const twilio = require("twilio");
const cors = require("cors");
const session = require("express-session");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");


// Config
const port = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const OTP_EXPIRY = 10 * 60 * 1000; // 10 minutes in milliseconds

// Middleware
app.use(helmet()); // Security headers
app.use(express.json());
app.use(cors({
  origin: "https://pomoc-zadluzonym.netlify.app",
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(session({ 
  secret: SESSION_SECRET, 
  resave: false, 
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Только в продакшене
    httpOnly: true,
     sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Zbyt wiele prób. Spróbuj ponownie później.' }
});
app.use('/api/', apiLimiter);

// OTP specific rate limiting
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit each IP to 5 OTP requests per hour
  message: { error: 'Zbyt wiele prób. Spróbuj ponownie później.' }
});

// Sanity client
const sanity = createClient({
  projectId: process.env.SANITY_PROJECT_ID,
  dataset: process.env.SANITY_DATASET,
  useCdn: process.env.NODE_ENV === 'production',
  apiVersion: "2025-03-07",
  token: process.env.SANITY_TOKEN,
});

// Twilio client
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { 
    fileSize: 5 * 1024 * 1024, // 5MB file size limit
    files: 10 
  },
  fileFilter: (req, file, cb) => {
    // Validate file types if needed
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'application/msword'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Nieprawidłowy typ pliku. Dozwolone są tylko pliki JPEG, PNG, PDF i DOC.'));
    }
  }
});

const isAuthenticated = (req, res, next) => {
  if (!req.session.authenticated) {
    return res.status(401).json({ error: "Brak dostępu" });
  }
  next();
};

// Validation functions
const validatePhone = (phone) => {
  const phoneRegex = /^\+?\d{7,15}$/;
  return phoneRegex.test(phone);
};

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

// Error handler middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err.stack);
  
  // Multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Plik jest za duży. Maksymalny rozmiar to 5MB.' });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  
  res.status(500).json({ error: "Internal server error" });
};

// Routes
app.get("/api/ping", (req, res) => {
  res.json({ message: "Server is running! 🚀" });
});

// Client routes
app.post("/api/clients", upload.array("files", 10), async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['name', 'phone'])) return;

    // Upload files to Sanity
    const fileUploads = req.files.map(async (file) => {
      const asset = await sanity.assets.upload("file", file.buffer, { filename: file.originalname });
      return {
        _key: crypto.randomUUID(),
        _type: "file",
        asset: { _type: "reference", _ref: asset._id }
      };
    });

    const uploadedFiles = await Promise.all(fileUploads);

    // Create document in Sanity
    const doc = {
      _type: "files",
      name: req.body.name,         
      phone: req.body.phone,
      files: uploadedFiles,
      createdAt: new Date().toISOString()
    };

    const result = await sanity.create(doc);
    res.status(201).json({ message: "Pliki zostały pomyślnie dodany", data: result });
  } catch (error) {
    next(error);
  }
});

app.post("/api/links", async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['name', 'phone', 'link'])) return;
    
    // URL validation
    try {
      new URL(req.body.link);
    } catch (e) {
      return res.status(400).json({ error: "Nieprawidłowy format adresu URL" });
    }

    // Create document in Sanity
    const doc = {
      _type: "link",
      name: req.body.name,
      phone: req.body.phone,
      link: req.body.link,
      createdAt: new Date().toISOString()
    };

    const result = await sanity.create(doc);
    res.status(201).json({ message: "Link został pomyślnie dodany", data: result });
  } catch (error) {
    next(error);
  }
});

// OTP routes
app.post("/api/send-otp", otpLimiter, async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['phone'])) return;

    // Generate 4-digit OTP
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    
    // First check if an OTP already exists
    const existingQuery = `*[_type == "otp" && phone == $phone][0]`;
    const existingOtp = await sanity.fetch(existingQuery, { phone: req.body.phone });
    
    if (existingOtp) {
      await sanity.delete(existingOtp._id);
    }

    // Send OTP via Twilio
    await twilioClient.messages.create({
      body: `Your verification code is: ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: req.body.phone
    });

    // Create OTP document in Sanity
    const doc = {
      _type: "otp",    
      otp,
      phone: req.body.phone,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + OTP_EXPIRY).toISOString()
    };

    const result = await sanity.create(doc);

    // Schedule OTP deletion
    setTimeout(async () => {
      try {
        const stillExists = await sanity.fetch(`*[_id == $id][0]._id`, { id: result._id });
        if (stillExists) {
          await sanity.delete(result._id);
          console.log(`OTP for ${req.body.phone} deleted from Sanity.`);
        }
      } catch (error) {
        console.error("Failed to delete OTP:", error.message);
      }
    }, OTP_EXPIRY);

    res.status(200).json({ message: "Kod potwierdzający został wysłany pomyślnie", phone: req.body.phone });
  } catch (error) {
    next(error);
  }
});

app.post("/api/validate-otp", async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['phone', 'otp'])) return;

    // Query Sanity for OTP
    const query = `*[_type == "otp" && phone == $phone][0]`;
    const otpRecord = await sanity.fetch(query, { phone: req.body.phone });

    if (!otpRecord) {
      return res.status(400).json({ error: "Kod weryfikacyjny nie znaleziony lub wygasł" });
    }

 

    // Check OTP
    if (otpRecord.otp !== req.body.otp) {
      return res.status(400).json({ error: "Nieprawidłowy kod weryfikacyjny" });
    }

    // Delete OTP after successful validation
    await sanity.delete(otpRecord._id);

    // You could set a session variable here to indicate authenticated state
    req.session.authenticated = true;
    req.session.phone = req.body.phone;

    res.status(200).json({ message: "Kod weryfikacyjny poprawnie zweryfikowany" });
  } catch (error) {
    next(error);
  }
});

// Apply error handler
app.use(errorHandler);

// Start server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    // Close any other resources or connections here
  });
});