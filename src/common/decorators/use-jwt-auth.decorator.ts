import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { createAuthDecorator } from '../functions/create-auth-decorator.function';

export const UseJwtAuth = createAuthDecorator(JwtAuthGuard);