import { PossessionAuthGuard } from '../guards/possession-auth.guard';
import { createAuthDecorator } from '../functions/create-auth-decorator.function';

export const UsePossessionAuth = createAuthDecorator(PossessionAuthGuard);