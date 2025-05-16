import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config(); // Load environment variables

const dbConnection = async (): Promise<void> => {
  try {
    const mongoUri = process.env.MONGO_URI as string;

    if (!mongoUri) {
      throw new Error("MONGO_URI is not defined in environment variables");
    }

    await mongoose.connect(mongoUri);
    console.log("✅ Connected to database!");
  } catch (error) {
    console.error("❌ Error connecting to the database: ", error);
  }
};

export default dbConnection;
