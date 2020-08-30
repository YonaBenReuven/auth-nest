import { createParamDecorator, ExecutionContext } from '@nestjs/common';

import { RequestUserType } from '../interfaces/request-user-type.interface';

export const RequestUser = createParamDecorator(
	(data: keyof RequestUserType, ctx: ExecutionContext) => {
		const request = ctx.switchToHttp().getRequest();
		const user = request.user as RequestUserType;

		return data ? user && user[data] : user;
	},
);