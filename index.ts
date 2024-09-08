import express, { Express } from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import UserRouter from './Router/user.router';
import SupplierRouter from './Router/supplier.routes';
import ProductRoute from './Router/product.routes';
import OrderRoute from './Router/order.routes';
import cors from 'cors';
import { config } from 'dotenv';
import connectDB from './Connect_DB/db_config';

// Load environment variables from .env file
config();

const app: Express = express();
let server: any = null; // Initialize server variable

// Middleware setup
app.use(cors()); // Enable CORS for cross-origin requests
app.use(bodyParser.json()); // Parse incoming JSON requests
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded data

// Route handling
app.use("/user", UserRouter); // Route for user-related endpoints
app.use("/supplier", SupplierRouter); // Route for supplier-related endpoints
app.use("/product", ProductRoute); // Route for product-related endpoints
app.use("/order", OrderRoute); // Route for order-related endpoints

// Database connection and server startup
const port = process.env.PORT || 3002; // Use environment port or default to 3002

const startServer = async () => {
    try {
        await connectDB(); // Ensure DB is connected
        server = app.listen(port, () => {
            console.log(`Server started on port ${port}...`);
        });
    } catch (error) {
        console.log("Failed to start server:", error);    }
};

const closeServer = async () => {
    if (server) {
        // Close the server
        await new Promise<void>((resolve, reject) => {
            server.close((err: Error) => {
                if (err) {
                    console.log('Error closing server:', err);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }
    // Disconnect from MongoDB
    await mongoose.disconnect();
    console.log('Server and database disconnected.');
};

export { startServer, closeServer }; // Export functions for testing or further configuration
export default app; // Export the app itself

// Start the server on script execution
if (require.main === module) {
    startServer();
}