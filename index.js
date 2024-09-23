const express = require("express");
const app = express();
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");
require("dotenv").config();

const cors = require("cors");

app.use(express.json());

app.use(cors());

connectDB();

app.use(express.json());
app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
