import { createTransport, Mailer } from 'nodemailer';
import { Injectable } from '@nestjs/common';
import { env } from 'process';
import { MailerInterface } from './mailer.interface';

@Injectable()
export class NodeMailerService implements MailerInterface {
    transporter: Mailer | null;
    constructor() {
        this.transporter = createTransport({
            service: 'gmail',
            host: 'smtp.gmail.com',
            port: 465,
            secure: true, // true for 465, false for other ports
            "auth": {
                "user": env.SEND_EMAIL_ADDR,
                "pass": env.SEND_EMAIL_PASS
            }
        });
    }

    send(data, cb?: Function) {
        return this.transporter.sendMail(data, cb)
    }

}