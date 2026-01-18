import aj from '#config/arcjet.js';
import logger from '#config/logger.js';
import { slidingWindow } from '@arcjet/node';

const securityMiddleware = async (req, res, next) => {
    try {
        const role = req.user?.role || 'guest';

        let limit;
        let message;

        if (role == 'admin') {
            limit = 20;
            message = 'User Type: "Admin" request limit exceeded (20 per minute) PLEASE SLOW DOWN !';
        }

        if (role == 'user') {
            limit = 10;
            message = 'User Type : "User" request limit exceeded (10 per minute) PLEASE SLOW DOWN !';
        }

        if (role == 'guest') {
            limit = 5;
            message = 'User Type : "Guest" request limit exceeded (5 per minute) PLEASE SLOW DOWN !';
        }
        
        const client = aj.withRule(
            slidingWindow({
                mode: 'LIVE',
                interval: '1m',
                max: limit,
                name: `${role}-rate-limit`,
            })
        );

        const decision = await client.protect(req);

        if (decision.isDenied() && decision.reason.isBot()) {
            logger.warn('Bot request blocked', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                path: req.path,
            });

            return res
                .status(403)
                .json({
                    error: 'Forbidden',
                    message: 'Automated requests are not allowed',
                });
        }

        if (decision.isDenied() && decision.reason.isShield()) {
            logger.warn('Shield Blocked request', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                path: req.path,
                method: req.method,
            });

            return res
                .status(403)
                .json({
                    error: 'Forbidden',
                    message: 'Request blocked by security policy',
                });
        }

        if (decision.isDenied() && decision.reason.isRateLimit()) {
            logger.warn('Rate limit exceeded', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                path: req.path,
            });

            return res
                .status(403)
                .json({ error: 'Forbidden', message: 'Too many requests' });
        }

        next();
    }
    catch (error) {
        console.log('Arc Jet Middleware Error : ', error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'Something went wrong in security middleware'
        });
    }
};

export default securityMiddleware;