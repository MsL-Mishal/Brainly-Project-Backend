import express from 'express';  // Express.js is a web application framework for Node.js. It is used to build web applications and APIs. It is a flexible and minimal framework that provides a wide range of features required for web and mobile application development. Mainly, it is used to build single-page, multi-page, and hybrid web applications. Express.js is built on top of Node.js, so it is a Node.js web application framework. It is used to create server-side applications with JavaScript. Express.js is a lightweight framework that helps to manage the flow of data between server and routes in the server-side applications. It is used to design the server-side of the application. Express.js is used to create a REST API server

import cookieparser from 'cookie-parser';   // Cookieparser is a middleware used to parse cookies in the request object. It is used to parse the Cookie header and populate req.cookies with an object keyed by the cookie names. You can use this middleware to parse the cookies in the request object. 

import cors from 'cors';    // CORS is a security feature used by browsers that prevents unauthorized cross-origin requests.The cors library in Express.js enables frontend-backend communication in MERN stack. You can allow specific origins using corsOptions. Now, your React frontend can fetch data from your Express.js backend without being blocked by CORS!

import { MONGO_URL } from './config';
import mongoose from 'mongoose';
import userRouter from './routes';

const port = 3000;
const app = express();

app.use(express.json());    // This is a built-in middleware function in Express. It parses incoming requests with JSON payloads and is based on body-parser. It is used to parse the incoming request body in JSON format. It is used to parse the incoming request object and populate req.body with the data. It is used to handle the JSON data in the request body.
app.use(cookieparser());    // This is a built-in middleware function in Express. It parses incoming requests with cookies and is based on cookie-parser. It is used to parse the Cookie header and populate req.cookies with an object keyed by the cookie names. You can use this middleware to parse the cookies in the request object.

/* 
//To restrict access to specific origins, you can customize CORS settings:

const corsOptions = {
    origin: 'http://localhost:3000', // Allow only this origin
    methods: 'GET,POST,PUT,DELETE',  // Allowed HTTP methods
    allowedHeaders: 'Content-Type,Authorization' // Allowed headers
};

app.use(cors(corsOptions));

//This allows only requests from http://localhost:3000, and only the GET, POST, PUT, and DELETE methods are allowed. The Content-Type and Authorization headers are allowed in the request.
*/

//To allow all origins, you can use the following code:
app.use(cors());

app.use('/api/v1', userRouter); //

async function main() 
{
    // Connect to the database

    //@ts-ignore
    await mongoose.connect(MONGO_URL);
    console.log("Connected to the Database");
    
    app.listen(port);
    console.log("Listening on Port " + port);
}

main();