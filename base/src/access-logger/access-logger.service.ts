import { User } from '../user/user.entity';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { Repository } from 'typeorm';
import { AccessLogger } from './access-logger.entity';
@Injectable()
export class AccessLoggerService {
    constructor(
        @InjectRepository(AccessLogger)
        private readonly accessLoggerRepository: Repository<AccessLogger>) { }

    async loginEvent(user: Partial<User>, success: boolean, minutes: number, tries: number) {
        const date = new Date();
        const minDate = new Date(date.getTime() - minutes * 60000);

        let day = minDate.getUTCDate();
        let month = ("0" + (minDate.getMonth() + 1)).slice(-2);
        let year = minDate.getFullYear();
        let hours = minDate.getHours();
        let mints = minDate.getMinutes();
        let seconds = minDate.getSeconds();

        let formatMinDate = year + "-" + month + "-" + day + " " + hours + ":" + mints + ":" + seconds;

        const loginCountsFailed = await this.accessLoggerRepository
            .createQueryBuilder('access_logger')
            .where(`date >= '${formatMinDate.toString()}' and userId = '${user.id}' and success = false`)
            .getCount();
        if (loginCountsFailed >= tries || !success) {
            await this.saveEvent(user, success, date);
            return false;
        }
        else {
            await this.accessLoggerRepository
                .createQueryBuilder('access_logger')
                .delete()
                .where(`userId = '${user.id}'`)
                .execute();
            await this.saveEvent(user, success, date);
            return true;
        }


    }

    async saveEvent(user: Partial<User>, success: boolean, date: Date) {
        let accessLogger = new AccessLogger();
        accessLogger.user = user as User;
        accessLogger.success = success;
        accessLogger.date = date;
        await this.accessLoggerRepository.save(accessLogger);
    }

}
