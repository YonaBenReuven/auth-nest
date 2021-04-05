import { applyDecorators, UseInterceptors } from '@nestjs/common';

import { JwtAuthInterceptor } from '../interceptors/jwt-auth.interceptor';
import { UserField } from './user-field.decorator';

export const UseJwtInterceptor = (userField: string = 'user') => applyDecorators(
	UserField(userField),
	UseInterceptors(JwtAuthInterceptor)
)