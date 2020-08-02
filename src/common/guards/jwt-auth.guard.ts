import { Injectable } from '@nestjs/common';

import { CreateAuthGuard } from '../functions/create-auth-guard.function';
import { UserService } from 'src/user/user.service';
import { Reflector } from '@nestjs/core';

@Injectable()
export class JwtAuthGuard extends CreateAuthGuard('jwt') {
	public readonly userService: UserService;
	public readonly reflector: Reflector;

	constructor(
		userService: UserService,
		reflector: Reflector
	) {
		super(userService, reflector);

		this.userService = userService;
		this.reflector = reflector;
	}
}