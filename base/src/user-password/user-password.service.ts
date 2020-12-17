import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { MoreThan, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { UserPassword } from './user-password.entity';
const debug = require('debug')("model:UserPasswords")

@Injectable()
export class UserPasswordService {
	constructor(
		@InjectRepository(UserPassword)
		private readonly userPasswordRepository: Repository<UserPassword>
	) { }

	async checkPassword(userId: string, password: string): Promise<boolean> {
		const userPasswords = await this.userPasswordRepository
			.createQueryBuilder('userPassword')
			.select('userPassword.id')
			.addSelect('userPassword.password')
			.innerJoin('userPassword.user', 'user', 'user.id = :userId', { userId })
			.orderBy('userPassword.id', 'DESC')
			.limit(3)
			.getMany();

		for (const userPassword of userPasswords) {
			if (bcrypt.compareSync(password, userPassword.password)) return false;
		}

		return true;
	}


	/**
	 * Checks if a year have pass since the last time the user changed his password.
	 */
	async changePasswordRequired(userId: string | number) {
		let date = new Date();
		date.setFullYear(date.getFullYear() - 1);
		let res = await this.userPasswordRepository.findOne({
			where: {
				created: MoreThan(date),
				user: { id: userId }
			}
		})
		debug('find password res:', res)
		return res ? false : true;//if there is a change-password record from the passed year, the user don't need to change.

	}

	createUserPassword(userId: string, password: string) {
		const userPassword = this.userPasswordRepository.create({ user: { id: userId }, password });

		return this.userPasswordRepository.save(userPassword);
	}
}
