import { User } from 'src/user/user.entity';

export interface UseAuthGuard {
	({ roles }: { roles: string[] }): ClassDecorator & MethodDecorator;

	<T extends (typeof User)[]>({ entities }: { entities: T }): ClassDecorator & MethodDecorator;

	<T extends (typeof User)[]>({ roles, entities }: { roles: string[], entities: T }): ClassDecorator & MethodDecorator;
	
	(...roles: string[]): ClassDecorator & MethodDecorator;

	<T extends (typeof User)[]>(...entities: T): ClassDecorator & MethodDecorator;
}
