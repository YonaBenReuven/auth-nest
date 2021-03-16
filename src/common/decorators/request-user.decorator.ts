import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

import { RequestUserType } from '../interfaces/request-user-type.interface';

export const RequestUser = createParamDecorator(
	(data: keyof RequestUserType, ctx: ExecutionContext) => {
		const request = ctx.switchToHttp().getRequest<Request>();
		const user = request.user as RequestUserType;

		return data ? user && user[data] : user;
	}
);