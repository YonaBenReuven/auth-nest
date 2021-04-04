import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

import { RequestUserType } from '../interfaces/request-user-type.interface';

export const RequestUser = createParamDecorator(
	(data: (keyof RequestUserType) | { data?: keyof RequestUserType; userField?: string }, ctx: ExecutionContext) => {
		const request = ctx.switchToHttp().getRequest<Request>();

		const userField = (typeof data === "object" && data.userField) || 'user';
		const user = request[userField] as RequestUserType;

		if (!user) return null;

		return data ? (typeof data === "object" ? (data.data ? user[data.data] : user) : user[data]) : user;
	}
);