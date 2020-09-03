import { Controller, Get, Param, Post, Res } from '@nestjs/common';
import { Response } from 'express';
import { UserService, UseLocalAuth, RequestUser, RequestUserType, UseJwtAuth } from '@hilma/auth-nest';

import { AppService } from './app.service';

@Controller()
export class AppController {
	constructor(
		private readonly appService: AppService,
		private readonly userService: UserService
	) { }

	@UseLocalAuth()
	@Post('login')
	login(@RequestUser() user: RequestUserType, @Res() res: Response) {
		const body = this.userService.login(user, res);
		res.send(body);
	}

	@UseJwtAuth()
	@Get('getStuff')
	getStuff(@RequestUser('id') id: string) {
		console.log(id);
	}

	@Get(':id')
	getRoles(@Param('id') id: string) {
		return this.userService.getRolesById(id);
	}

	@Get()
	getHello(): string {
		return this.appService.getHello();
	}
}
