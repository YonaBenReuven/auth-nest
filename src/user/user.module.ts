import { Module, DynamicModule } from '@nestjs/common';

import { UserConfig } from './user.config.interface';
import { createUserModuleMetadata } from '../common/functions/create-user-module-metadata.function';

@Module(createUserModuleMetadata())
export class UserModule {
	static register(options: UserConfig): DynamicModule {
		return {
			module: UserModule,
			...createUserModuleMetadata(options)
		};
	}
}
