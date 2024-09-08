import mongoose, { Document, Model, Schema } from 'mongoose';
import bcrypt from 'bcryptjs';

// Interface defining the properties of the User document
interface IUser extends Document {
    userId: string; // Primary Key
    name: string; // New property for user's name
    email: string;
    passwordHash: string; // Renamed to match your previous schema
    role: 'Viewer' | 'Content Creator' | 'Admin';
    createdAt: Date;
    updatedAt: Date;
}

// Interface for static methods of the User model
interface IUserModel extends Model<IUser> {
    checkPassword(password: string, hashedPassword: string): boolean;
}

// Define the schema
const userSchema = new Schema<IUser>({
    userId: {
        type: String,
        required: true,
        unique: true,
        default: () => new mongoose.Types.ObjectId().toString(), // Automatically generate a unique ID
    },
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
    },
    passwordHash: {
        type: String,
        required: true,
        trim: true,
        set: (password: string) => {
            const salt = bcrypt.genSaltSync(10);
            return bcrypt.hashSync(password, salt);
        },
    },
    role: {
        type: String,
        required: true,
        enum: ['Viewer', 'Content Creator', 'Admin'],
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    }
}, {
    versionKey: false,
    timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' } // Automatically handles createdAt and updatedAt fields
});

// Static method to compare passwords
userSchema.statics.checkPassword = function (password: string, hashedPassword: string): boolean {
    return bcrypt.compareSync(password, hashedPassword);
};

// Create the model
const User: IUserModel = mongoose.model<IUser, IUserModel>('User', userSchema);

export default User;
