const express = require('express')
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const fs = require('fs')
const path = require('path')
const app = express();
app.use(express.json())

const saltRounds = 10;
const users = [];

const privateKey = fs.readFileSync(path.join(__dirname, 'keys', 'rsa.key'), 'utf8')
const publicKey = fs.readFileSync(path.join(__dirname, 'keys', 'rsa.key.pub'), 'utf8')


app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(404).json({ message: 'Invalid Username' });
    }

    bcrypt.compare(password, user.password, function(err, result) {
        if(err)
            return res.status(500).json({ message: 'Something went wrong. Please try again!' })
        if(result){
            const token = jwt.sign({ username: user.username }, privateKey, { algorithm:'RS256',expiresIn: '1h'});
            res.json({ token });
        }else{
            res.status(401).json({ message: 'Invalid Password' })
        }
    });

});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
  
    jwt.verify(token, publicKey, {algorithms:['RS256']}, (err, user) => {
      if (err) {
        console.log(err)
        return res.status(403).json({ message: 'Invalid token' });
      }
      const userInfo = users.find(usr=>usr.username===user.username)
      if(userInfo?.role==='admin')
        req.user = {...user,role:'admin'};
      else{
          req.user = user
      }
      next();
    });
    
}  

app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Protected route accessed successfully' });
});


app.post('/register',(req,res)=>{
    const user = req.body;
    if(user.username && user.password && user.role){
        const userExists = users.findIndex(usr=>usr.username===user.username)
        if(userExists===-1){
            bcrypt.hash(user.password, saltRounds, function(err, hash) {
                let tempUser = {
                    username:user.username,
                    role: user.role,
                    password: hash
                }
                users.push(tempUser)
                return res.json({
                    user:tempUser.username,
                    status:"Registration successful!"
                })
            });
        }else{
            res.status(400).json({message: "User already exists!"})
        }
    }else{
        res.status(400).json({message: "Bad Request! All fields are mandatory"})
    }
})

app.get('/admin',authenticateToken, (req,res)=>{
    if(req.user.role === 'admin')
        return res.json({message: "Welcome to admin!"})
    return res.json({message: "You're not authorized to access this!"})
})

app.get('/user',authenticateToken, (req,res)=>{
    return res.json({message: "Welcome "+req.user.username})
})

const PORT = 3000
app.listen(PORT, () => {
    console.log(`listenting on port ${PORT}...`)
})