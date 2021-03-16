import { User } from '../../user/user.entity';

export interface UseAuthGuard {
	<T extends (typeof User)[]>(config: { roles: string[], entities: T }): ClassDecorator & MethodDecorator;

	<T extends (typeof User)[]>(config: { roles?: string[], entities: T }): ClassDecorator & MethodDecorator;

	<T extends (typeof User)[]>(config: { roles: string[], entities?: T }): ClassDecorator & MethodDecorator;

	(...roles: string[]): ClassDecorator & MethodDecorator;

	<T extends (typeof User)[]>(...entities: T): ClassDecorator & MethodDecorator;
}
