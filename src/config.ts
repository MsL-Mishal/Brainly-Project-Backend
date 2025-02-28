import { config } from 'dotenv';
config();

export const MONGO_URL = process.env.MONGO_URL;
export const JWT_SECRET : string = String(process.env.JWT_SECRET);