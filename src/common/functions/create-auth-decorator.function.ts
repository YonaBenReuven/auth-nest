import { applyDecorators, CanActivate, UseGuards } from '@nestjs/common';

import { UseJwtInterceptor } from '../decorators/use-jwt-interceptor.decorator';
import { SetAuthMetadata } from '../decorators/set-auth-metadata.decorator';
import { UseAuthGuard } from '../interfaces/use-auth-guard.interface';
import { User } from '../../user/user.entity';

import { AuthGuard } from './auth-guard.function';

export const createAuthDecorator = (Guard: CanActivate | Function | ReturnType<typeof AuthGuard>): UseAuthGuard => <T extends typeof User>(
	config?: any,
	...rest: any
) => {
	if (config === '$everyone' && (Guard as ReturnType<typeof AuthGuard>).type === 'jwt') return applyDecorators(
		UseJwtInterceptor()
	);

	return applyDecorators(
		SetAuthMetadata(config, ...rest),
		UseGuards(Guard)
	);
}