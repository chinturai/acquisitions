import jwt, { sign } from "jsonwebtoken";
import logger from './../config/logger';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = '1d';

export const jwt_token = {
    sign : (payload) => {
        try {
            return jwt.sign( payload , JWT_SECRET, {expiresIn : JWT_EXPIRES_IN});
        } catch (error) {
            logger.error('Authentication Failed :( ', error);
            throw new Error('Failed to Authenticate Token');
        }
    },
    verify : (token) => {
        try {
            jwt.verify(token, JWT_SECRET);
        } catch (error) {
            logger.error('Token Verification Failed :( ', error);
            throw new Error('Failed to Verify Token');
        }
    }
}