const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

require("dotenv").config();

app.use(express.json())
app.use(cookieParser());


const { OAuth2Client } = require("google-auth-library");

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = "http://localhost:8080/auth/google/callback";

const client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

app.post('/verify-token', async (req, res) => {
  const { token } = req.body;

  try {
    // Verify the ID token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: CLIENT_ID,
    });

    // Extract the user information from the verified token
    const payload = ticket.getPayload();
    const userId = payload.sub;
    const userEmail = payload.email;
    console.log(payload);


    // Do further processing or authentication with the obtained user information

    // Respond with a success message
    res.json({ success: true });
  } catch (error) {
    // Handle any verification errors
    console.error('Token verification error:', error);
    res.status(400).json({ success: false, error: 'Invalid token' });
  }
});


// callback from google
app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;
  // console.log(req.query);
  try {
    const { tokens } = await client.getToken(code);
    console.log('tototo token :', tokens);

    client.setCredentials(tokens);

    // get user informations
    const { data } = await client.request({
      url: "https://www.googleapis.com/oauth2/v1/userinfo?alt=json",
      method: "GET",
    });

    console.log("google data : ", data);

    // use JWT to create token and store it in session or cookies
    const token = jwt.sign(
      {
        ...data,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });

    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.get("/auth/google", (req, res) => {
  // Generate the url that will be used for the consent dialog.
  const authUrl = client.generateAuthUrl({
    access_type: "offline",
    scope: ["email", "profile"],
  });

  res.redirect(authUrl);
});

const jwtAuthMiddleware = (req, res, next) => {
  const cookies = req.cookies;
  // console.log("Cookies:", cookies);

  // no cookies or no token provide send status 401 unauthorized
  if (!cookies || !cookies.token) {
    return res.status(401).send("Unauthorized");
  }

  const token = req.cookies.token;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // sent user data through request
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Error verifying JWT token:", err);
    return res.status(401).json({ message: "Unauthorized", err });
  }
};

app.get("/", jwtAuthMiddleware, (req, res) => {
  // console.log(req.user);

  res.send(`Hello ${req.user.name}!`);
});

app.get("/logout", (req, res) => {
  // clear token in cookie to make user logout
  res.clearCookie("token");
  // redirects the request back to the referrer, "/" by default
  res.redirect("back");
  // avoid web request hanging
  res.end();
});

app.listen(8080, () => console.log("Listening at port 8080"));
