var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = '@2G4#Y7!t0z2$4S6&8*01P3KA%7BN1X3'

app.use(cors())
const sql = require('mssql')
const config = {
    user: 'ac_api',
    password: '@cipa2023',
    server: 'ahthkab20vt', // You can use 'localhost\\instance' to connect to named instance
    database: 'AccountAPI',
    options: {
        encrypt: true, // Use encryption for security (if needed)
        trustServerCertificate: true, // Ignore SSL validation
    },
}


//POST API
app.post('/register', jsonParser, async (req, res) => {
    try {
        // Connect to the database
        const pool = await sql.connect(config);

        // Hash the password
        const salt = await bcrypt.genSalt(saltRounds);
        const hash = await bcrypt.hash(req.body.password, salt);

        // Perform the INSERT operation
        const result = await pool
            .request()
            .input('email', sql.VarChar, req.body.email)
            .input('password', sql.Text, hash)
            .input('fname', sql.VarChar, req.body.fname)
            .input('lname', sql.VarChar, req.body.lname)
            .query('INSERT INTO tb_account (email, password, fname, lname) VALUES (@email, @password, @fname, @lname)');
        
        sql.close(); // Close the connection

        // Send a response
        res.json({ status: 'ok' });

    } catch (error) {
        console.error('Error inserting data:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

app.post('/login', jsonParser, async (req, res) => {
    try {
        // Connect to the database
        const pool = await sql.connect(config);

        // Retrieve user's record by email
        const result = await pool
            .request()
            .input('email', sql.VarChar, req.body.email)
            .query('SELECT password FROM tb_account WHERE email = @email');
        
        if (result.recordset.length === 0) {
            // No user found with the given email
            res.status(401).json({ message: 'Invalid email or password' });
            return;
        }

        const hashedPasswordFromDB = result.recordset[0].password;

        // Compare the provided password with the hashed password from the database
        const passwordMatch = await bcrypt.compare(req.body.password, hashedPasswordFromDB);

        if (!passwordMatch) {
            // Passwords do not match
            res.status(401).json({ message: 'Invalid email or password' });
            return;
        }
        var token = jwt.sign({ email: req.body.email }, secret,{ expiresIn: '1h' });
        // Passwords match, user is authenticated
        res.json({status:'ok',token });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'An error occurred' });
    }
});

app.post('/authen', jsonParser, (req, res) => {
    try{
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({status:'ok',decoded})
        res.json({decoded})
    }catch(err){
        res.json({status:'error',message: err.message})
    }

})

 
app.listen(3333, function () {
   console.log('CORS-enabled web server listening on port 3333')
 })