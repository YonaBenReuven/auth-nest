import { Controller, Post, Res } from '@nestjs/common';
import { Response } from 'express';
import { RequestUser, RequestUserType, UserService, UseLocalAuth } from '@hilma/auth-nest';

import { Admin } from './admin.entity';

@Controller('admin')
export class AdminController {
	constructor(
		private readonly userService: UserService
	) { }

	@UseLocalAuth(Admin)
	@Post('login')
	login(@RequestUser() user: RequestUserType, @Res() res: Response) {
		const body = this.userService.login(user, res);
		res.send(body);
	}
}