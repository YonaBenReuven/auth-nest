import { Request } from 'express';

export const extractTokenFromCookie = (cookieName: string) => (req: Request) => {
	return req.cookies && req.cookies[cookieName] || null;
}