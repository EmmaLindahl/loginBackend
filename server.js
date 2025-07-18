const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;
const fs = require('fs');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const SECRET_KEY = 'your-secret-key';

app.use(cors())
app.use(express.json());
app.get('/', (req, res) => {
    res.json("Server is working!");
});

//Use this to authenticate user, when they make sensitive POST req. Like delete user, money transfer.
// const authenticateToken = (req, res, next) => {
//     const authHeader = req.headers['authorization'];
//     const token = authHeader && authHeader.split(' ')[1];
//     if (!token) {
//     return res.status(401).json({ message: 'Access token missing' });
//   }

//   jwt.verify(token, SECRET_KEY, (err, user) => {
//     if (err) return res.status(403).json({ message: 'Invalid or expired token' });
//     req.user = user; // user = decoded token payload, e.g., { username: '...' }
//     next();
//   });
// }

app.post('/register', async(req, res) => {
    if (!req.body.username || !req.body.password) {
        return res.status(400).json({message: 'Username & password are required'});
    }
    const {username, password} = req.body;
    
    if(username && password){
        //Note! Only fetching all users because I use a json file instead of database.
        const usersData = fs.readFileSync('users.json', 'utf8')
        const users = JSON.parse(usersData)
        const exists = users.find(u => u.username === username);
        
        if(exists){
            return res.status(409).json({message: 'Username already taken'})
        }else{ 
            const hashedPassword = await bcrypt.hash(password, 10)
            const newDatabase = [...users, {username: username, password: hashedPassword}]
            fs.writeFileSync('users.json', JSON.stringify(newDatabase, null, 2))
            return res.status(201).json({message:'You now have a user'})
        }

    }
    
}) 

app.post('/login', async(req, res) => {
    const {username, password} = req.body;
    if (!req.body.username || !req.body.password) {
        return res.status(400).json({message: 'Username & password are required'});
    }

    const usersData = fs.readFileSync('users.json', 'utf8')
    const users = JSON.parse(usersData)

    const user = users.find(u => u.username === username);
    if(!user){
        return res.status(401).json({message:"User not found"});
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch){
        return res.status(401).json({message:"incorrect password"});
    }
    const token = jwt.sign({username}, SECRET_KEY, {expiresIn: '1h'});
    res.status(200).json({message: "Login successful!", token})
});

app.post('/delete', async(req, res) =>{
    const {username, password} = req.body;
    if (!req.body.username || !req.body.password) {
        return res.status(400).json({message: 'Username & password are required'});
    }
    const usersData = fs.readFileSync('users.json', 'utf8');
    const users = JSON.parse(usersData)

    const user = users.find(u => u.username === username)
    if(!user){
        return res.status(401).json({message:"User not found"});
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch){
        return res.status(401).json({message:"incorrect password"});
    }
    const newDatabase = users.filter((u) => u.username != username )
    fs.writeFileSync('users.json', JSON.stringify(newDatabase))
    res.status(200).json({message: "Account deleted successfully"})
})

app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`)
})