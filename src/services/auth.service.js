import bcrypt from 'bcrypt';
import logger from '#config/logger.js';
import {db} from '#config/database.js';
import { users } from '#models/user.model.js';

export const hashPassword = async (password) => {
    try {
        return await bcrypt.hash(password, 10);
    } catch (error) {
        logger.error('Error while hashing the password :( ');
        throw new Error('Error while hashing the password :( ');
    }
}

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (e) {
    logger.error(`Error comparing password: ${e}`);
    throw new Error('Error comparing password');
  }
};

export const createUser = async ({ name, email, role = 'user'}) => {
    try {
        // Check if user already exist or not
        const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

        if(existingUser.length > 0){
            throw new Error('User already exists');
        }
        
        // Start Process of Creating the User
        const hash_password = await hashPassword(password);
        
        const [newUser] = await db
        .insert(users)
        .values({
            name, 
            email, 
            password: hash_password,
            role
        })
        .returning({
            id : users.name, 
            name : users.name,
            email : users.email,
            role : users.role,
            created_at : users.created_at
        });

        logger.info(`User ${email} created Successfully ! `);
        
        return newUser;
    } catch (error) {
        logger.error('Error while Creating the User : ', error);
        throw new Error('Error while Creating the User : ', error);
    }
}

export const authenticateUser = async ({ email, password }) => {
  try {
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!existingUser) {
      throw new Error('User not found');
    }

    const isPasswordValid = await comparePassword(
      password,
      existingUser.password
    );

    if (!isPasswordValid) {
      throw new Error('Invalid password');
    }

    logger.info(`User ${existingUser.email} authenticated successfully`);
    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
      created_at: existingUser.created_at,
    };
  } catch (e) {
    logger.error(`Error authenticating user: ${e}`);
    throw e;
  }
};

