import { Injectable, Inject } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { EmailUser } from './email-user.entity';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import UserConfigOptions from 'src/user/userConfigOptions';
import { UserService } from 'src/user/user.service';
@Injectable()
export class EmailUserService extends UserService {
    constructor(
        @Inject('CONFIG_OPTIONS') protected config_options: UserConfigOptions,
        @InjectRepository(EmailUser)
        protected readonly userRepository: Repository<EmailUser>,
        protected readonly jwtService: JwtService,
        protected readonly configService: ConfigService
    ) {
        super(config_options, userRepository, jwtService, configService);

        // this.sendVerificationEmail("reut.schremer@carmel6000.amitnet.org", "lalala");
    }



    googleLogin(req) {
        if (!req.user) {
            return 'No user from google'
        }

        return {
            message: 'User information from google',
            user: req.user
        }
    }
}
