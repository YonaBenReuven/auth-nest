import { UseGuards, applyDecorators } from '@nestjs/common';

import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { Roles } from './roles.decorator';

export const UseJwtAuth = (...roles: string[]) => applyDecorators(
	Roles(...roles),
	UseGuards(JwtAuthGuard)
);