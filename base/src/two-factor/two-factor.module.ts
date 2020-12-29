import { DynamicModule, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';

import { defaultTwoFactorOptions, TWO_FACTOR_OPTIONS } from '../common/constants';
import { User } from '../user/user.entity';
import { TwoFactorOptions } from '../common/interfaces/two-factor-options.interface';
import { KnowledgeStrategy } from '../common/strategies/knowledge.strategy';
import { PossessionStrategy } from '../common/strategies/possession.strategy';
import { UserModule } from '../user/user.module';

import { TwoFactor } from './two-factor.entity';
import { TwoFactorService } from './two-factor.service';

@Module({
	imports: [
		TypeOrmModule.forFeature([TwoFactor, User]),
		JwtModule.register({}),
		UserModule
	],
	providers: [
		TwoFactorService,
		KnowledgeStrategy,
		PossessionStrategy,
		{
			provide: TWO_FACTOR_OPTIONS,
			useValue: defaultTwoFactorOptions
		}
	],
	exports: [JwtModule.register({}), TwoFactorService]
})
export class TwoFactorModule {
	static register(options: TwoFactorOptions = {}): DynamicModule {
		return {
			module: TwoFactorModule,
			providers: [
				{
					provide: TWO_FACTOR_OPTIONS,
					useValue: { ...defaultTwoFactorOptions, ...options }
				}
			]
		}
	}
}
