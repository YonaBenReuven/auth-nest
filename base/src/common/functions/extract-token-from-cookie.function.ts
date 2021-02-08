import { Request } from 'express';

export const extractTokenFromCookie = (cookieName: string, queryAccessToken: boolean) => (req: Request) => {
	return req.cookies && req.cookies[cookieName] || req.headers && req.headers.authorization || queryAccessToken && req.query && req.query[cookieName] || null;
}