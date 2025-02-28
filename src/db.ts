import mongoose, {Schema, model} from "mongoose";
const ObjectId = Schema.Types.ObjectId;

const usersSchema = new Schema({
    username: {type: String, unique: true, required: true},
    password: {type: String, required: true}
});

export const users = model('users', usersSchema);

const tagsSchema = new Schema({
    title: {type: String, required: true, unique: true}
});

export const tagsModel = model('tagsModel', tagsSchema);

const contentTypes = ['image', 'video', 'article', 'audio'];

// - Relationships in mongoose
// Mongoose does not enforce strict relationships** the way relational databases (like MySQL or PostgreSQL) do. In a relational database, foreign keys and constraints would enforce that a reference to another table must exist, and an error would be thrown if you tried to insert a reference to a non-existent record. However, Mongoose and MongoDB do not impose such constraints by default.

// How to Enforce Validation:
// 1. Using validate

const contentSchema = new Schema({
    link: {type: String, required: true},
    type: {type: String, enum: contentTypes, required: true},
    title: {type: String, required: true},
    tags: [{type: ObjectId, ref: tagsModel}],
    userId: {
        type: ObjectId, 
        ref: users, 
        required: true,
        validate: async function(value: string) {
            const user = await users.findById(value);
            if (!user) {
              throw new Error('User does not exist');
            }
        }
    }
});

export const content = model('content', contentSchema);

// 2. Using pre-save hook

/*

contentSchema.pre('save', async function(next) {
  const user = await users.findById(this.userId);
  if (!user) {
    throw new Error('User does not exist');
  }
  next();
});

*/

const linkSchema = new Schema({
    hash: {type: String, required: true},
    userId: {type: ObjectId, ref: users, required: true}
});

export const link = model('link', linkSchema);