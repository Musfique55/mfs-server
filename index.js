const express = require('express');
const app = express();
const port = 3000;
const cors = require('cors');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

require('dotenv').config();
app.use(cors());
app.use(express.json());




const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.jaoth1x.mongodb.net/?appName=Cluster0`;

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
    await client.connect();
    
    const usersDB = client.db('mfsDB').collection('users');

    // jwt
app.post('/jwt',(req,res) => {
    const user = req.body;
    const token = jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{expiresIn : '1h'})
    res.send({token})
})
    
app.post('/users',async(req,res) => { 
    const myPlaintextPassword = req.body.pin;
    bcrypt.genSalt(saltRounds,(err,salt) => {
        bcrypt.hash(myPlaintextPassword,salt,async(err,hash)=> {
            if(err){
                console.log(err);
            }else{
                const user = {
                   name :  req.body.name,
                   email : req.body.email,
                   mobile : req.body.number,
                   pin : hash,
                   status : 'pending'
                };
                const result = await usersDB.insertOne(user);
                res.send(result);

            }
        })
    })
})

app.post('/login',async(req,res) => {
        const identifier = req.body.emailMobile;
        const pin = req.body.pin;
        const query = identifier.includes('@') ? {email : identifier} : {mobile : identifier};
        const user = await usersDB.findOne(query);
        const doc = {
        $set : { available : true}
        }
        if(user && await bcrypt.compare(pin,user.pin)){
            await usersDB.updateOne(query,doc)
            res.status(200).send(user.available);
        }else{
            res.send(false);
        }
    })

    app.post('/logout',async(req,res) => {
        const identifier = req.body.emailMobile;
        const query = identifier.includes('@') ? { email : identifier} : {mobile : identifier}
        const doc = {
            $set : {available : req.body.available}
        }
        await usersDB.updateOne(query,doc);
      
    })
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);




app.get('/',(req,res) => {
    res.send('mfs server is running');
})



app.listen(port,() => {
    console.log(`server is running on ${port}`);
})