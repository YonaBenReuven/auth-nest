import { LocalAuthGuard } from '../guards/local-auth.guard';
import { createAuthDecorator } from '../functions/create-auth-decorator.function';

export const UseLocalAuth = createAuthDecorator(LocalAuthGuard);