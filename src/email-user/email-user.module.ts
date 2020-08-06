import { Module, DynamicModule } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EmailUser } from './email-user.entity';
import { EmailUserService } from './email-user.service';
import { EmailUserController } from './email-user.controller';
import UserConfigOptions from 'src/user/userConfigOptions';

import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from 'src/common/constants';
import { RoleModule } from 'src/role/role.module';
import { GoogleStrategy } from 'src/common/strategies/oauth2.strategy';

const userModule = (options: UserConfigOptions = new UserConfigOptions()) => ({
    imports: [
        RoleModule,
        TypeOrmModule.forFeature([EmailUser]),
        JwtModule.register({
            secret: jwtConstants.secret,
            signOptions: { expiresIn: '100min' },
        })
    ],
    providers: [
        {
            provide: 'CONFIG_OPTIONS',
            useValue: options,
        },
        EmailUserService,
        GoogleStrategy
    ],
    exports: [EmailUserService],
    controllers: [EmailUserController]

})

@Module(userModule({ verifyPath: "/email-user/verify" }))

export class EmailUserModule {
    static register(options: UserConfigOptions = new UserConfigOptions({ verifyPath: "/email-user/verify" })): DynamicModule {
        return { module: EmailUserModule, ...userModule(options) };
    }
}