const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt');
const session = require('express-session');
const crypto = require('crypto');
// const User = require('./user');

const secretKey = crypto.randomBytes(64).toString('hex');
const port = process.env.PORT || 5000;

const MAX_LOGIN_ATTEMPTS = 4;
const LOCK_TIME = 30 * 60 * 1000;

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: secretKey,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 5 * 60 * 1000 } 
}));

const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).send({ error: true, message: 'unauthorized access' });
  }

  const token = authorization.split(' ')[1];

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).send({ error: true, message: 'unauthorized access' })
    }
    req.decoded = decoded;
    next();
  })
}
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const uri = "mongodb://irfanali:12345@ac-o9yzcgk-shard-00-00.ymwhs5q.mongodb.net:27017,ac-o9yzcgk-shard-00-01.ymwhs5q.mongodb.net:27017,ac-o9yzcgk-shard-00-02.ymwhs5q.mongodb.net:27017/?ssl=true&replicaSet=atlas-xges0x-shard-0&authSource=admin&retryWrites=true&w=majority"


const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
   
    const usersCollection = client.db("workzen").collection("users");
    const jobsCollection = client.db("workzen").collection("jobs");
    

    app.get('/api/reset-activity', (req, res) => {
      req.session.destroy();
      res.json({ message: 'Activity reset.' });
    });

    
    app.get('/users', async (req, res) => {
        const result = await usersCollection.find({role:"user"}).toArray();
        res.send(result);
      });
    app.get('/hosts', async (req, res) => {
        const result = await usersCollection.find({role: "host"}).toArray();
        res.send(result);
      });

      app.post('/users', async (req, res) => {
        const user = req.body;
        
        const query = { email: user.email }
        const existingUser = await usersCollection.findOne(query);
  
        if (existingUser) {
          return res.send({ message: 'user already exists' })
        }
  
        const result = await usersCollection.insertOne(user);
        res.send(result);
      });

      app.post('/signup', async (req, res) => {
        const {name,email,image,role,password,isLocked,lockUntil,loginAttempts} = req.body;
      
        const query = { email }
        const existingUser = await usersCollection.findOne(query);
        if (existingUser) {
          return res.send({ message: 'user already exists' })
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
          name,
          email,
          image,
          role,
          password: hashedPassword,
          isLocked,
          lockUntil,
          loginAttempts
        };
        const result = await usersCollection.insertOne(newUser);
        res.send(result);
      });


      app.post('/login', async (req, res) => {
        const { email, password } = req.body;      
        try {
          const query = { email }
        const user = await usersCollection.findOne(query);
        
        if (!user) {
          return res.send({ message: 'Invalid credentials' })
        }
          
        if (user.isLocked) {
          const now = new Date();        
      
          if (now < user.lockUntil) {
         
            return res.status(403).json({ message: 'Account locked. Try again later.' });
          }
          
          await usersCollection.updateOne(
            { query },
            {
              $set: { isLocked: false, loginAttempts: 0 },
              $unset: { lockUntil: '' },
            }
          );
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
          await usersCollection.updateOne(
            {query},
            {
              $inc: { loginAttempts: 1 },
              $set: { lockUntil: user.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS ? new Date(Date.now() + LOCK_TIME) : undefined },
              $set: { isLocked: user.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS },
            }
          );
         
          return res.status(401).json({ message: 'Invalid credentials' });
        }
    
        await usersCollection.updateOne(
          { query },
          {
            $set: { lastLogin: new Date(), loginAttempts: 0 },
            $unset: { lockUntil: '', isLocked: '' },
          }
        );
       
    
        res.status(200).json({ message: 'Login successful' });
      } catch (error) {
        res.status(500).json({ message: 'Error during login' });
      }
        
      }
      );

      app.get('/selected', async (req, res) => {
        const result = await jobsCollection.find({select: "selected"}).toArray();
        res.send(result);
      });

   
      app.get('/jobs', async (req, res) => {
        const result = await jobsCollection.find().toArray();
        res.send(result);
      })
  
  
      app.get('/jobpage', async (req, res) => {
        const result = await jobsCollection.find({status: "approved"}).toArray();
        res.send(result);
      })
  
      app.post('/jobs', async (req, res) => {
        const newItem = req.body;
        const result = await jobsCollection.insertOne(newItem)
        res.send(result);
      })



       //, verifyJWT
    app.get('/users/host/:email', async (req, res) => {
        const email = req.params.email;
       
        // if (req.decoded.email !== email) {
        //   res.send({ instructor: false })
        // }
        
        const query = { email: email }
        
        const user = await usersCollection.findOne(query);
        
        const result = { host: user?.role === 'host' }
       
        res.send(result);
      })
      //, verifyJWT
      app.get('/users/admin/:email', async (req, res) => {
        const email = req.params.email;
       
        // if (req.decoded.email !== email) {
        //   res.send({ admin: false })
        // }
        
        const query = { email: email }
       
        const user = await usersCollection.findOne(query);
        
        const result = { admin: user?.role === 'admin' }
       
        res.send(result);
      })
      app.get('/users/user/:email', async (req, res) => {
        const email = req.params.email;
       
        // if (req.decoded.email !== email) {
        //   res.send({ admin: false })
        // }
        
        const query = { email: email }
       
        const user = await usersCollection.findOne(query);
        //  console.log(user)
        
        const result = { user: user?.role === 'user' }
       
        res.send(result);
      })
  
      app.patch('/users/admin/:id', async (req, res) => {
        const id = req.params.id;
        console.log(id);
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: 'admin'
          },
        };
  
        const result = await usersCollection.updateOne(filter, updateDoc);
        res.send(result);
  
      })
      app.patch('/users/host/:id', async (req, res) => {
        const id = req.params.id;
        // console.log(id);
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: 'host'
          },
        };
  
        const result = await usersCollection.updateOne(filter, updateDoc);
        res.send(result);
  
      })
     
  
  
  
      app.patch('/job/approved/:id', async (req, res) => {
        const id = req.params.id;
        // console.log(id);
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            status: 'approved'
          },
        };
  
        const result = await classesCollection.updateOne(filter, updateDoc);
        res.send(result);
  
      })
      app.patch('/job/apply/:id', async (req, res) => {
        const id = req.params.id;
        // console.log(id);
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            apply: 'done'
          },
        };
  
        const result = await jobsCollection.updateOne(filter, updateDoc);
        res.send(result);
  
      })
      app.patch('/job/denied/:id', async (req, res) => {
        const id = req.params.id;
        console.log(id);
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            status: 'denied'
          },
        };
  
        const result = await classesCollection.updateOne(filter, updateDoc);
        res.send(result);
  
      })
      app.get('/apply', async (req, res) => {
        const result = await jobsCollection.find({apply: "done"}).toArray();
        res.send(result);
      });
      
     

// Send a ping to confirm a successful connection
await client.db("admin").command({ ping: 1 });
console.log("Pinged your deployment. You successfully connected to MongoDB!");
} finally {
// Ensures that the client will close when you finish/error
// await client.close();
}
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('jobs')
  })
  
  app.listen(port, () => {
    console.log("hello jobs");
  })