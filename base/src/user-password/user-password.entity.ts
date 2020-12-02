import { Column, Entity, ManyToOne, PrimaryGeneratedColumn, BeforeInsert } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { SALT } from '../common/constants';
import { User } from '../user/user.entity';

@Entity()
export class UserPassword {
	@PrimaryGeneratedColumn()
	id: number;

	@Column()
	password: string;

	@ManyToOne(type => User)
	user: User;

	@BeforeInsert()
	async hashPassword() {
		if (this.password)
			this.password = await bcrypt.hash(this.password, SALT);
	}
}