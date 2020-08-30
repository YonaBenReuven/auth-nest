import { Controller, Get, Param, Post, Res } from '@nestjs/common';
import { Response } from 'express';

import { AppService } from './app.service';
import { UserService } from './user/user.service';
import { UseLocalAuth } from './common/decorators/use-local-auth.decorator';
import { RequestUser } from './common/decorators/request-user.decorator';
import { RequestUserType } from './common/interfaces/request-user-type.interface';
import { UseJwtAuth } from './common/decorators/use-jwt-auth.decorator';

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
