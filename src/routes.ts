import { Router, Request, Response } from "express";
import { z } from 'zod';   // Zod is a TypeScript-first schema declaration and validation library. It is used to validate the incoming request body in the routes
import bcrypt from 'bcrypt';    // Used for hashing the password
import jwt from "jsonwebtoken"; // Used for generating the JWT token
import { users, tagsModel, content, link } from './db';
import { JWT_SECRET } from "./config";
import { authenticateTokenMiddleware } from "./middleware";

const userRouter = Router();    // Creates a new router object

// Defining the zod schema for user signup
const userSignupSchema = z.object({
    username: z.string().regex(/^[a-zA-Z\d]{3,10}$/, { message: 'Username must be 3-10 characters long and contain only letters and digits' }),
    password: z.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/, { message: 'Password must be 8-20 characters long and contain atleast one uppercase, one lowercase, one special character, one number' })
});

type userSignupType = z.infer<typeof userSignupSchema>;

// Defining the zod schema for content
const contentSchema = z.object({
    link: z.string().url().min(1, { message: 'Link cannot be empty' }),
    type: z.enum(['image', 'video', 'article', 'audio']),
    title: z.string().min(1, { message: 'Title cannot be empty' }),
    tags: z.array(z.string()).min(1, { message: 'At least one tag is required' })
});

type contentType = z.infer<typeof contentSchema>;

// Defining the zod schema for share content
const shareSchema = z.boolean();

type shareType = z.infer<typeof shareSchema>;

// Route 1: Create a signup route

//@ts-ignore
userRouter.post('/signup', async (req: Request, res: Response) => {
    // Todo1: zod validation

    const validationResult = userSignupSchema.safeParse(req.body);

    if (!validationResult.success) {
        return res.status(400).json({ message: 'Validation failed', errors: validationResult.error.errors });
    }

    const { username, password } = validationResult.data;

    // Todo2: hash the password

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the number of salt rounds

        // Todo3: save the user to the database if the username is not taken

        const user = await users.findOne({ username });

        if (user) {
            return res.status(409).json({ message: 'Username already taken' });
        }

        await users.create({ 
            username: username, 
            password: hashedPassword 
        });

        return res.status(200).json({ message: 'Signup successful', data: {username, hashedPassword} });
    }

    catch (e: any) {
        console.error(e);
        return res.status(500).json({ message: 'Error hashing password', error: e.message });
    }
});

// Route 2: Create a signin route

//@ts-ignore
userRouter.post('/signin', async (req: Request, res: Response) => {

    try {
        // Todo1: zod validation

        const validationResult = userSignupSchema.safeParse(req.body);

        if (!validationResult.success) {
            return res.status(400).json({ message: 'Validation failed', errors: validationResult.error.errors });
        }

        const { username, password } = validationResult.data;

        // Todo1: check if the user exists

        const user = await users.findOne({ username });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Todo2: check if the password is correct
        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Incorrect password' });
        }

        // Todo3: generate a JWT token

        const token = jwt.sign({
            id: user._id.toString() 
        }, JWT_SECRET, { expiresIn: '1h' }); // token expires in 1 hour

        res.cookie('token', token, { 
            httpOnly: true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : 'strict',
            maxAge : 24*60*60*1000  // sets 1 day as cookie expiry
        });

        res.status(200).json({ message: 'Signin successful', data: { token } });
    }
    
    catch (e: any) {
        console.error(e);
        return res.status(500).json({ message: 'Internal Server Error', error: e.message });
    }
});

// Interface to extend the Request interface to include the userId field, so that we can access the userId in the request object in the routes without any errors
interface AuthenticatedRequest extends Request {
    userId: string;
}

// Route 3: Create a post content route

//@ts-ignore
userRouter.post('/content', authenticateTokenMiddleware, async (req: AuthenticatedRequest, res: Response) => {
    try {
        // Todo1: zod validation

        const validationResult = contentSchema.safeParse(req.body);

        if (!validationResult.success) {
            return res.status(400).json({ message: 'Validation failed', errors: validationResult.error.errors });
        }

        const { link, type, title, tags } = validationResult.data;

        if (tags.length > 5) {
            return res.status(400).json({ message: 'Maximum 5 tags are allowed' });
        }

        else if (tags.length <= 5 && tags.length > 0) {
            const existingTags = await tagsModel.find();

            const existingTagTitles = existingTags.map((tag) => tag.title);

            const newTags = tags.filter((tag) => !existingTagTitles.includes(tag));

            for (const tag of newTags) {
                await tagsModel.create({ title: tag });
            }
        }
        
        //@ts-ignore
        const userId = req.userId;

        const tagsData = await tagsModel.find({ title: { $in: tags } });

        // Todo2: save the content to the database

        await content.create({
            link,
            type,
            title,
            tags: tagsData.map((tag) => tag._id),
            userId
        });

        return res.status(200).json({ message: 'Content created successfully'});

    }
    catch(e: any) {
        console.error(e);
        return res.status(500).json({ message: 'Internal Server Error', error: e.message });
    
    }

});

// Route 4: Create a get content route

// @ts-ignore
userRouter.get('/content', authenticateTokenMiddleware, async (req: AuthenticatedRequest, res: Response) => {
    try {
        
        // @ts-ignore
        const userId = req.userId;

        // Todo1: get the content from the database

        const data = await content.find({ userId }).populate('userId', 'username').populate('tags', 'title').exec(); // fetches the content, and the coresponding `username` and `title` fields from the `users` and `tagsModel` collections respectively by using the `ref` field in the `content` schema and here `populate` is used to fetch the data from the referenced collections. The first argument in the `populate` function is the name of the field in the `content` schema that references the other collection. The second argument in the `populate` function is the fields that we want to fetch from the referenced collections which can be a single field or multiple fields that are separated by space.

        return res.status(200).json({ message: 'Content fetched successfully', data });
    }

    catch(e: any) {
        console.error(e);
        return res.status(500).json({ message: 'Internal Server Error', error: e.message });

    }
});

// Route 5: Create a delete content route

//@ts-ignore
userRouter.delete('/content', authenticateTokenMiddleware, async (req: AuthenticatedRequest, res: Response) => {

    try {
        
        const contentId = req.body.contentId;

        if(!contentId) {
            return res.status(400).json({ message: 'Content Id is required' });
        }

        const userId = req.userId;

        const contentData = await content.findOne({ _id: contentId, userId });

        if (!contentData) {
            return res.status(404).json({ message: 'Content not found' });
        }

        else if (contentData.userId.toString() !== userId) {
            return res.status(403).json({ message: 'Unauthorized access' });
        }

        // Todo1: delete the content from the database
        await content.deleteMany({ _id: contentId, userId });

        return res.status(200).json({ message: 'Content deleted successfully' });
    }    

    catch(e: any) {
        console.error(e);
        return res.status(500).json({ message: 'Internal Server Error', error: e.message });
    }
});

// Route 6: Create a share content route

// Create a shareable link for your second brain which sets { "share": true, } and returns { "link": "link_to_open_brain" }

//@ts-ignore
userRouter.post('/brainly/share', authenticateTokenMiddleware, async (req: AuthenticatedRequest, res: Response) => {

        // Todo1: create a shareable link for the second brain

        try {

            const userId = req.userId;

            const validationResult = shareSchema.safeParse(req.body);

            if (!validationResult.success) {
                return res.status(400).json({ message: 'Validation failed', errors: validationResult.error.errors });
            }

            const share = validationResult.data;

            if (share) {
                const existingLink = await link.findOne({ userId });

                if (existingLink) {
                    return res.json({ 
                        hash: existingLink.hash 
                    });
                }

                const hash = Math.random().toString(36).substring(7); // generates a random hash

                await link.create({ 
                    hash: hash, 
                    userId: userId 
                });

                return res.status(200).json({ message: 'Link created successfully', data: { link: hash } });

            }
    
            else {
                await link.deleteOne({ userId });

                res.status(200).json({ message: 'Link deleted successfully' });
            }
        }
            
        catch(e: any) {
            console.error(e);
            return res.status(500).json({ message: 'Internal Server Error', error: e.message });
        }

});

// Route 7: Create a get shared content route

//@ts-ignore
userRouter.get('/brainly/:shareLink', async (req: Request, res: Response) => {

    try {
        const shareLink = req.params.shareLink;

        // Todo1: get the shared content from the database

        const linkData = await link.findOne({ hash: shareLink });

        if(!linkData) {
            return res.status(404).json({ message: 'Link not found' });
        }

        const userId = linkData.userId;

        const contentData = await content.find({ userId }).populate('userId', 'username').populate('tags', 'title').exec();

        console.log(linkData);

        const userData = await users.findOne({ _id: userId });

        if(!userData) {
            return res.status(404).json({ message: 'User not found, error should ideally not happen' });
        }

        const userName = userData.username;

        return res.status(200).json({ message: 'Content fetched successfully', data: { contentData, userName } });
    }

    catch(e: any) {
        console.error(e);
        return res.status(500).json({ message: 'Internal Server Error', error: e.message });
    }
});

export default userRouter;