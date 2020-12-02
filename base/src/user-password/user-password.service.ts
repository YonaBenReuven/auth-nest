import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { UserPassword } from './user-password.entity';

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

	createUserPassword(userId: string, password: string) {
		const userPassword = this.userPasswordRepository.create({ user: { id: userId }, password });

		return this.userPasswordRepository.save(userPassword);
	}
}
