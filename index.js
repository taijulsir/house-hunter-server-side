const express = require("express")
const cors = require("cors")
require("dotenv").config()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const app = express()
const port = process.env.PORT || 5000;

app.use(cors())
app.use(express.json())


const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.49cfwvw.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const userCollection = client.db("houseHunterDB").collection('users')


        // API for jwt send token in client side
        app.post('/api/jwt', async (req, res) => {
            try {
                const user = req.body;
                const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
                    expiresIn: '1h'
                });
                res.send(token)
            }
            catch (error) {
                console.error("Error in  jwt endpoint ", error);
                res.status(500).send({ error: "Internal Server Error" })
            }
        })


        // API for get registered user data
        app.post('/api/register',async(req,res)=>{
            const user = req.body;
            const email = user.email
            const query = {email: email}
            // check the duplicated users
            const existingUser = await userCollection.findOne(query)
            if(existingUser){
              return  res.status(200).send({message: "User already exists", insertedId: null})
            }
            // hash the password
            const hashedPassword = await bcrypt.hash(req.body.password,10);
            
            // save user to the database
            const newUser = new ({
                name: req.body.name,
                role: req.body.role,
                phoneNumber: req.body.phoneNumber,
                email: req.body.email,
                photoUrl : req.body.photoUrl,
                password: hashedPassword
            })
            const result = await userCollection.insertOne(newUser)
            res.send(result)
        })

        // Api for user login endpoint
        app.post('/api/login',async(req,res)=>{
            const {email,password} = req.body
            const emailQuery = {email: email}
            // verify email 
            const user = await userCollection.findOne(emailQuery)
            if(!user){
              return  res.status(401).send({error: "Invalid Credentials"})
            }
            
            // Verify password

            const validPassword = await bcrypt.compare(password, user.password)
            if(!validPassword){
                return res.send(401).send({error: "Invalid Credentials"})
            }
            res.status(200).send({message : "Login ssuccesfull"})

        })

        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get("/", (req, res) => {
    try {
        res.send("The house hunter server side is running")
    }
    catch (error) {
        res.status(500).send("Internal server error", error.message)
    }
})

app.listen(port, () => {
    console.log(`The server is running on port ${port}`)
})