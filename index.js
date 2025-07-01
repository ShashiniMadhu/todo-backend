require('dotenv').config();
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const PORT = process.env.PORT || 8080;
const MONGOURL = process.env.MONGOURL;

app.use(express.json());

// console.log('Connecting to MongoDB:', process.env.MONGOURL);
// Remove deprecated options
mongoose.connect(process.env.MONGOURL)
    .then(() => console.log("✅ Connected to MongoDB Atlas"))
    .catch((err) => console.error("❌ MongoDB connection error:", err));


const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});

const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
    text: String,
    status: String,
    priority: String,
    userId: mongoose.Schema.Types.ObjectId
});

const Task = mongoose.model('Task', taskSchema);

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashed = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashed });
        await user.save();
        res.json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Registration failed', error: error.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        // Fixed: was "await_User" instead of "await User"
        const user = await User.findOne({ username: username });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Login failed', error: error.message });
    }
});

const authMiddleware = (req, res, next) => {
    // Fixed: headers is a property, not a function
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    try {
        // Fixed: was "decose" instead of "decode", and use process.env.JWT_SECRET
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decode.userId;
        next();
    } catch (e) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Create a new task for the authenticated user
// Fixed: added authMiddleware to protect the route
app.post('/tasks', authMiddleware, async (req, res) => {
    try {
        const task = new Task({ ...req.body, userId: req.userId });
        await task.save();
        res.status(201).json({ message: "Task created successfully", task });
    } catch (error) {
        res.status(500).json({ message: "Task creation failed", error: error.message });
    }
});

//Get all tasks for the authenticated user
app.get('/tasks', authMiddleware, async (req, res) => {
    try {
        const tasks = await Task.find({ userId: req.userId });
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ message: 'Failed to retrieve tasks', error: error.message });
    }
});


//Delete a task by ID for the authenticated user
// Fixed: added authMiddleware to protect the route
app.delete("/tasks/:id", authMiddleware, async (req, res) => {
    await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    res.json({ message: 'Task deleted successfully' });
});

// Update a task by ID for the authenticated user
// Fixed: added authMiddleware to protect the route
app.put("/tasks/:id", authMiddleware, async (req, res) => {
    const { status } = req.body;

    try {
        const task = await Task.findOneAndUpdate(
            { _id: req.params.id, userId: req.userId }, // ✅ Correct way to match task and user
            { status },
            { new: true }
        );

        if (!task) {
            return res.status(404).json({ message: 'Task not found' });
        }

        res.json({ message: 'Task updated successfully', task });
    } catch (error) {
        res.status(500).json({ message: 'Update failed', error: error.message });
    }
});

// Update task priority by ID for the authenticated user
// Fixed: added authMiddleware to protect the route
app.patch("/tasks/:id/priority", authMiddleware, async (req, res) => {
    const { priority } = req.body;
    const task = await Task.findByIdAndUpdate(
        { _id: req.params.id, userId: req.userId },
        { priority },
        { new: true }
    );
    if (!task) {
        return res.status(404).json({ message: 'Task not found' });
    }
    res.json(task);
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));