const express = require("express")
const cors = require("cors")
require("dotenv").config()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const app = express()
const port = process.env.PORT || 5000;

app.use(cors())
app.use(express.json())


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
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
        const houseCollection = client.db("houseHunterDB").collection('houses')
        const bookingHouseCollection = client.db("houseHunterDB").collection('bookingHouses')


        // middlewares for verify token
        const verifyToken = async (req, res, next) => {
            try {
                if (!req.headers.authorization) {
                    return res.status(401).json({ message: "Unauthorized access" })
                }
                const token = req.headers.authorization.split(' ')[1];
                jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                    if (err) {
                        return res.status(401).json({ message: "Unauthorized access" })
                    }
                    req.decoded = decoded;
                    next();
                })
            }
            catch (error) {
                console.error("Error in verifyToken middleware", error)
                return res.status(500).json({ message: "Internal server error" })
            }
        }

        // middlewares for check user role
        const verifyOwner = async (req, res, next) => {
            try {
                const email = req.decoded.email;
                const query = { email: email }
                const user = await userCollection.findOne(query)
                const isOwner = user?.role === 'owner';
                if (isOwner) {
                    next();
                }
                else {
                    return res.status(403).json({ message: "Forbidden access" })
                }
            }
            catch (error) {
                console.log("Error occuered in verify admin", error)
                res.status(500).json({ message: "Internal server error" })
            }
        }

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

        // Check admin    
        app.get('/api/user/checkRole/:email', verifyToken, async (req, res) => {
            try {
                const email = req.params.email;
                if (email !== req.decoded.email) {
                    return res.status(403).json({ message: "Forbidden Access" })
                }
                const query = { email: email }
                const user = await userCollection.findOne(query)
                let role = {
                    owner: false,
                    renter: false,
                }
                if (user) {
                    role.owner = user?.role === 'owner';
                    role.renter = user?.role === 'renter'
                }
                res.send({ role })
            }
            catch (error) {
                console.error("Error in checking user role", error)
                res.status(500).json({ message: "Internal server error" })
            }
        })

        // API for user register endpoint
        app.post('/api/register', async (req, res) => {
            const user = req.body;
            const email = user.email
            const query = { email: email }
            try {
                // Check for duplicated users
                const existingUser = await userCollection.findOne(query);
                if (existingUser) {
                    return res.status(200).json({ message: "User already exists", insertedId: null });
                }

                // Hash the password
                const hashedPassword = await bcrypt.hash(req.body.password, 10);

                // Save user to the database
                const newUser = {
                    name: req.body.name,
                    role: req.body.role,
                    phoneNumber: req.body.phoneNumber,
                    email: req.body.email,
                    photoUrl: req.body.photoUrl,
                    password: hashedPassword
                };

                const result = await userCollection.insertOne(newUser);
                const insertedId = result.insertedId;

                // Send response with the insertedId
                res.json({ message: "User registered successfully", insertedId });
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Internal Server Error", insertedId: null });
            }
        });

        // Api for user login endpoint
        app.post('/api/login', async (req, res) => {
            try {
                const { email, password } = req.body
                const emailQuery = { email: email }
                // verify email 
                const user = await userCollection.findOne(emailQuery)
                if (!user) {
                    return res.status(401).json({ error: "Invalid Credentials" })
                }

                // Verify password

                const validPassword = await bcrypt.compare(password, user.password)
                if (!validPassword) {
                    return res.status(401).json({ error: "Invalid Credentials" })
                }
                res.status(200).json({ message: "Login ssuccesfull" })
            }
            catch (error) {
                console.error("Error ocurred in login", error.message)
                res.status(500).json({ message: "Internal server error" })
            }
        })

        // API for get specific user data
        app.get('/api/user/:email', async (req, res) => {
            try {
                const email = req.params.email;
                const query = { email: email }
                const result = await userCollection.findOne(query)
                res.status(200).json(result)
            }
            catch (error) {
                console.error("Error in find user", error.message)
                res.status(500).json({ error: "Internal server error" })
            }
        })

        // Api for create new house
        app.post('/api/createNewHouse', async (req, res) => {
            try {
                const houseInfo = req.body;
                const result = await houseCollection.insertOne(houseInfo)
                res.status(200).json(result)
            }
            catch (error) {
                console.error("Error occured in create new house", error)
                res.status(500).json({ message: "Internal server error" })
            }
        })

        // Api for get all house
        app.get("/api/houses", async (req, res) => {
            try {
                const result = await houseCollection.find().toArray()
                res.status(200).json(result)
            }
            catch (error) {
                console.error("Error occured in get all houses", error)
                res.status(500).json({ message: "Internal server error" })
            }
        })
        // APi for get house specific user
        app.get("/api/house/user/:email", async (req, res) => {
            try {
                const email = req.params.email;
                const query = { ownerEmail: email }
                const result = await houseCollection.find(query).toArray()
                res.status(200).json(result)
            }
            catch (error) {
                console.error("Error occured in get all houses", error)
                res.status(500).json({ message: "Internal server error" })
            }
        })

        // APi for get single house info
        app.get("/api/singleHouse/:id", async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) }
                const result = await houseCollection.findOne(query)
                res.status(200).json(result)
            }
            catch (error) {
                console.error("Error occured in get all houses", error)
                res.status(500).json({ message: "Internal server error" })
            }
        })

        // API for delete house
        app.delete("/api/deleteHouse/:id", async (req, res) => {
            try {
                const id = req.params.id;
                console.log(id)
                const query = { _id: new ObjectId(id) }
                console.log(query)
                const result = await houseCollection.deleteOne(query)
                console.log(result)
                res.status(200).json(result)
            }
            catch (error) {
                console.error("Error occured in delete a houses", error)
                res.status(500).json({ message: "Internal server error" })
            }
        })

        // APi for update a specific house
        app.put("/api/updateHouse/:id", async (req, res) => {
            try {
                const houseInfo = req.body;
                const id = req.params.id;
                const query = { _id: new ObjectId(id) }
                const options = { upsert: true };
                const updatedHouse = {
                    $set: {
                        name: houseInfo.name,
                        address: houseInfo.address,
                        city: houseInfo.city,
                        bedrooms: houseInfo.bedrooms,
                        bathrooms: houseInfo.bathrooms,
                        size: houseInfo.size,
                        picture: houseInfo.picture,
                        availabilityDate: houseInfo.availabilityDate,
                        rentPerMonth: houseInfo.rentPerMonth,
                        phoneNumber: houseInfo.phoneNumber,
                        description: houseInfo.description,
                        ownerEmail: houseInfo.ownerEmail,
                        ownerName: houseInfo.ownerName,
                        ownerImage: houseInfo.ownerImage
                    }
                }
                const result = await houseCollection.updateOne(query, updatedHouse, options)
                res.status(200).json(result)
            }
            catch {
                console.error("Error occured in get all houses", error)
                res.status(500).json({ message: "Internal server error" })
            }
        })

        // Api for booking houses
        app.post("/api/bookHouse", async (req, res) => {
            try {
                const bookHouse = req.body;
                const result = await bookingHouseCollection.insertOne(bookHouse)
                res.status(200).json(result)
            }
            catch{
                console.error("Error occured in create booking houses", error)
                res.status(500).json({ message: "Internal server error" })     
            }
        })

        // Api for get booking houses
        app.get("/api/bookHouse/:email",async(req,res)=>{
           try{
            const email = req.params.email;
            const query = {renterEmail: email}
            const result = await bookingHouseCollection.find(query).toArray()
            res.status(200).json(result)
           }
           catch{
            console.error("Error occured in get booking houses", error)
            res.status(500).json({ message: "Internal server error" })
           }
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