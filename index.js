const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const User = require("./models/UserModel");
const Message = require("./models/MessageModel");
const ws = require("ws");
const fs = require("fs");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

dotenv.config();
mongoose.connect(process.env.MONGO_URL,)
  .then(() => {
    console.log("Successfully connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

const app = express();
app.use(express.json());
app.use(cookieParser());
// const allowedOrigins = ["https://chatapp-rosy-eta.vercel.app/"];

const corsOptions = {
  origin: 'https://chatapp-rosy-eta.vercel.app', // Replace with your frontend URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // If you need to allow credentials such as cookies
};

// Use CORS middleware
app.use(cors(corsOptions));

const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

// Set up Cloudinary storage for multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "profile_images", // Cloudinary folder name
    allowed_formats: ["jpg", "jpeg", "png"],
  },
});
const upload = multer({ storage: storage });


const bucketName = process.env.AWS_S3_BUCKET_NAME;

async function uploadToS3(fileName, filePath) {
  const fileContent = fs.readFileSync(filePath);
  const command = new PutObjectCommand({
    Bucket: bucketName,
    Key: fileName,
    Body: fileContent,
    ACL: "public-read",
  });

  await s3Client.send(command);

  // Generate a public URL
  const url = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
  return url.split("?")[0]; // Remove query parameters to get the public URL
}

async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, jwtSecret, {}, (err, userData) => {
        if (err) throw err;
        resolve(userData);
      });
    } else {
      reject("no token");
    }
  });
}

app.get("/", (req, res) => {
  res.json("test is running ok");
});

app.get("/messages/:userId", async (req, res) => {
  const { userId } = req.params;
  const userData = await getUserDataFromRequest(req);
  const ourUserId = userData.userId;
  const messages = await Message.find({
    sender: { $in: [userId, ourUserId] },
    recipient: { $in: [userId, ourUserId] },
  }).sort({ createdAt: 1 });
  res.json(messages);
});

app.get("/people", async (req, res) => {
  try {
    const users = await User.find({}, { _id: 1, username: 1, profileImage: 1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users", error });
  }
});


const nodemailer = require("nodemailer");

// Nodemailer setup
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com", // You can use other services like SendGrid, etc.
  port:465,
  secure: true, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER, // Your email address
    pass: process.env.EMAIL_PASS, // Your email password
  },
});

// Registration route
app.post("/register", upload.single("profileImage"), async (req, res) => {

  const { username, password, email } = req.body;
  console.log("register:", username, password,email);

  try {
    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" });
    }

    // Hash the password
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);

    // Get the uploaded image URL
    const profileImageUrl = req.file ? req.file.path : "";

    // Create a new user with an unverified status
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
      email: email,
      profileImage: profileImageUrl,
      isVerified: false, // User is not verified yet
    });

    // Generate JWT token for email verification
    jwt.sign(
      { userId: createdUser._id, username, email },
      jwtSecret,
      { expiresIn: '1d' }, // Token valid for 1 day
      async (err, token) => {
        if (err) {
          return res.status(500).json({ error: "Error generating verification token" });
        }

        // Email verification link
        const verificationLink = `https://chatappback-9eg8.onrender.com/verify-email?token=${token}`;

        // Send verification email
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Verify your email address",
          html: `<p>Hi ${username},</p>
                 <p>Please click on the link below to verify your email address:</p>
                 <a href="${verificationLink}">Verify Email</a>`,
        });

        res.status(201).json({ message: "Registration successful. Please verify your email." });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Email verification route
app.get("/verify-email", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ error: "Missing token" });
  }

  // Verify JWT token
  jwt.verify(token, jwtSecret, async (err, decoded) => {
    if (err) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }

    // Find the user and update their verification status
    const { userId } = decoded;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.isVerified = true;
    await user.save();

    res.json({ message: "Email successfully verified. You can now log in." });
  });
});


app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const foundUser = await User.findOne({ username });

    if (!foundUser) {
      return res.status(404).json({ error: "User not registered" });
    }

    if (!foundUser.isVerified) {
      return res.status(401).json({ error: "Please verify your email before logging in" });
    }

    const passOk = bcrypt.compareSync(password, foundUser.password);

    if (!passOk) {
      return res.status(401).json({ error: "Invalid password" });
    }

    jwt.sign(
      { userId: foundUser._id, username },
      process.env.JWT_SECRET,
      {},
      (err, token) => {
        if (err) {
          return res.status(500).json({ error: "Server error" });
        }

        res.cookie("token", token, { sameSite: "none", secure: true }).json({
          id: foundUser._id,
          username: foundUser.username,
          token,
          userProfile: foundUser.profileImage,
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});


app.post("/logout", (req, res) => {
  res.cookie("token", "", { sameSite: "none", secure: true }).json("ok");
});
// app.post("/register", upload.single("profileImage"), async (req, res) => {
//   const { username, password } = req.body;
//   console.log("register:", username, password);

//   try {
//     // Check if the username already exists
//     const existingUser = await User.findOne({ username });
//     if (existingUser) {
//       return res.status(400).json({ error: "Username already exists" });
//     }

//     // Hash the password
//     const hashedPassword = bcrypt.hashSync(password, bcryptSalt);

//     // Get the uploaded image URL (store it on a cloud service or file system)
//     const profileImageUrl = req.file ? req.file.path : ""; // Replace with your Cloudinary URL logic

//     // Create a new user
//     const createdUser = await User.create({
//       username: username,
//       password: hashedPassword,
//       profileImage: profileImageUrl, // Save the image URL in the database
//     });

//     // Generate JWT token
//     jwt.sign(
//       { userId: createdUser._id, username },
//       jwtSecret,
//       {},
//       (err, token) => {
//         if (err) {
//           return res.status(500).json({ error: "Error generating token" });
//         }
//         res
//           .cookie("token", token, { sameSite: "none", secure: true })
//           .status(201)
//           .json({ id: createdUser._id });
//       }
//     );
//   } catch (err) {
//     // Handle MongoDB duplicate key error
//     if (err.code === 11000) {
//       return res.status(400).json({ error: "Username already exists" });
//     }

//     res.status(500).json({ error: "Internal Server Error" });
//   }
// });
const port = 8001;
const server = app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const wss = new ws.WebSocketServer({ server });
wss.on("connection", (connection, req) => {
  function notifyAboutOnlinePeople() {
    const onlineClients = [...wss.clients].filter((client) => client.userId);
    onlineClients.forEach((client) => {
      client.send(
        JSON.stringify({
          online: onlineClients.map((c) => ({
            userId: c.userId,
            username: c.username,
          })),
        })
      );
    });
  }

  connection.isAlive = true;

  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
      console.log("dead");
    }, 1000);
  }, 5000);

  connection.on("pong", () => {
    clearTimeout(connection.deathTimer);
  });

  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies
      .split(";")
      .find((str) => str.trim().startsWith("token="));
    if (tokenCookieString) {
      const token = tokenCookieString.split("=")[1];
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          if (err) return connection.close(); // Close connection if token verification fails
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
          notifyAboutOnlinePeople(); // Notify about online people once authenticated
        });
      }
    }
  }

  connection.on("message", async (message) => {
    const messageData = JSON.parse(message.toString());
    const { recipient, text, file } = messageData;
    let fileUrl = null;
    if (file) {
      const parts = file.name.split(".");
      const ext = parts[parts.length - 1];
      const fileName = `${Date.now()}.${ext}`;
      const filePath = `uploads/${fileName}`;
      const bufferData = Buffer.from(file.data.split(",")[1], "base64");
      fs.writeFileSync(filePath, bufferData);

      // Upload to AWS S3
      fileUrl = await uploadToS3(fileName, filePath);
    }
    if (recipient && (text || fileUrl)) {
      const messageDoc = await Message.create({
        sender: connection.userId,
        recipient,
        text,
        file: fileUrl ? fileUrl : null,
      });
      [...wss.clients]
        .filter((c) => c.userId === recipient)
        .forEach((c) =>
          c.send(
            JSON.stringify({
              text,
              sender: connection.userId,
              recipient,
              file: fileUrl ? fileUrl : null,
              _id: messageDoc._id,
            })
          )
        );
    }
  });

  connection.on("close", () => {
    notifyAboutOnlinePeople(); // Notify about online people when someone disconnects
  });

  notifyAboutOnlinePeople(); // Notify about online people when someone connects
});
