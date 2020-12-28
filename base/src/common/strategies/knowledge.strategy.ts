import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

import { LoginErrorCodes } from '../loginErrorCodes';
import { UserService } from '../../user/user.service';
import { TwoFactorService } from '../../two-factor/two-factor.service';

@Injectable()
export class KnowledgeStrategy extends PassportStrategy(Strategy, 'knowledge') {
	constructor(
		private readonly userService: UserService,
		private readonly twoFactorService: TwoFactorService
	) {
		super();
	}

	async validate(username: string, password: string) {
		try {
			const user = await this.userService.validateUser(username, password);
			if (!user) {
				throw new UnauthorizedException();
			}
			await this.twoFactorService.validateUser(user.id);
			return user;
		} catch (err) {
			if (err.key in LoginErrorCodes)
				throw new UnauthorizedException(err);
			else {
				console.error("error in local strategy", err);
				throw new UnauthorizedException();
			}
		}
	}
}
