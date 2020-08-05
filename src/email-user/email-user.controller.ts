import { Controller, Post, Get, Param, Query, Res } from '@nestjs/common';
import { EmailUserService } from './email-user.service';
import { Response } from 'express';
import { EmailUser } from './email-user.entity';


@Controller('email-user')
export class EmailUserController {
    constructor(
        private readonly emailService: EmailUserService
    ) {
        let user = new EmailUser();
        user.username = "reut.schremer@carmel6000.amitnet.org"
        user.password = "123123";
        // this.emailService.createUser(user);
    }

    @Post('/login')
    login() { }

    @Get('/verify')
    async verifyByMail(@Query('token') token: string, @Res() res: Response) {
        console.log("verifieng ");
        if (!token) {
            return res.send("No token supplied")
        }
        let success = await this.emailService.verifyEmailByToken(token);
        res.send("success:" + success)
    }

}
