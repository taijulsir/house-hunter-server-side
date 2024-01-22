const express = require("express")
const cors = require("cors")
require("dotenv").config()
const app = express()
const port = process.env.PORT || 5000;

app.use(cors())
app.use(express.json())

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